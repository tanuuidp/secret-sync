package vault

import (
	"context"
	"strings"
	"sync-secrets/pkg/helper"
	"sync-secrets/pkg/secret"

	vault "github.com/hashicorp/vault/api"
	auth "github.com/hashicorp/vault/api/auth/kubernetes"
	log "github.com/sirupsen/logrus"
)

const (
	EnvAddr     = "VAULT_ADDR"
	EnvKubeRole = "VAULT_KUBERNETES_ROLE"
	EnvEngine   = "VAULT_SECRETS_ENGINE"
	EnvToken    = "VAULT_TOKEN"

	DefaultEngine = "secrets"
)

type Vault struct {
	Address string
	Auth    struct {
		Token          string
		KubernetesRole string
	}
	Config  *vault.Config
	Client  *vault.Client
	Engine  string
	Secrets []*secret.Secret
}

// New returns a new Vault struct. Configurations are read from environment variables. The envPrefix
// is used to check for non-generic configs (used as a prefix for the variables), as more Vaults
// could be configured for the same session. Any generic variable is also checked if prefixed option
// does not exist.
//
// For example, New("SOURCE_") will first get value from "SOURCE_VAULT_ADDR". If not found, tries to
// get value from "VAULT_ADDR".
func New(envPrefix string) *Vault {
	v := Vault{}
	fields := log.Fields{"system": "HashiCorp Vault"}

	if e := helper.Getenv(envPrefix, EnvAddr); e != "" {
		v.Address = e
		fields["url"] = e
	} else {
		log.WithFields(fields).Fatalf("%s not defined, cannot connect", envPrefix+EnvAddr)
	}

	if e := helper.Getenv(envPrefix, EnvKubeRole); e != "" {
		v.Auth.KubernetesRole = e
		v.Auth.Token = ""
		fields["kubernetes-role"] = e
	} else if e := helper.Getenv(envPrefix, EnvToken); e != "" {
		v.Auth.KubernetesRole = ""
		v.Auth.Token = e
	} else {
		log.WithFields(fields).Fatalf("%s or %s not defined, cannot authenticate", envPrefix+EnvKubeRole, envPrefix+EnvToken)
	}

	if e := helper.Getenv(envPrefix, EnvEngine); e != "" {
		v.Engine = e
	} else {
		v.Engine = DefaultEngine
	}
	fields["secrets-engine"] = v.Engine

	config := vault.DefaultConfig()
	config.Address = v.Address

	log.WithFields(fields).Infof("Connecting to HashiCorp Vault")

	client, err := vault.NewClient(config)
	if err != nil {
		log.WithFields(fields).WithError(err).Fatal("unable to initialize Vault client")
	}

	if v.Auth.KubernetesRole != "" {
		// Kubernetes auth
		k8sAuth, err := auth.NewKubernetesAuth(v.Auth.KubernetesRole)
		if err != nil {
			log.WithFields(fields).WithError(err).Fatal("Failed to initialize Kubernetes auth")
		}

		authInfo, err := client.Auth().Login(context.TODO(), k8sAuth)
		if err != nil {
			log.WithFields(fields).WithError(err).Fatal("Unable to log in with Kubernetes auth")
		}
		if authInfo == nil {
			log.WithFields(fields).WithError(err).Fatal("No auth info was returned after login")
		}

	} else {
		// Token auth
		client.SetToken(v.Auth.Token)
	}

	v.Config = config
	v.Client = client

	if !v.hasEngine(v.Engine) {
		log.WithFields(fields).Infof("Secrets Engine %s does not exist", v.Engine)
		v.createKvEngine(v.Engine)
	}

	return &v
}

// CleanRemovedSecrets compares each secret in newSecrets and curSecrets. If a secret in the latter
// does not exist in the prior, it is considered removed from the source system and will be deleted
// from Vault as well.
func (v *Vault) CleanRemovedSecrets(newSecrets []*secret.Secret) {
	var removedSecrets uint32
	var secretFound bool

	// Check which secrets are removed
	for _, cur := range v.Secrets {
		secretFound = false
		for _, new := range newSecrets {
			if cur.EqualName(new) {
				secretFound = true
				break
			}
		}

		if !secretFound {
			log.WithFields(log.Fields{
				"path":   cur.Name,
				"system": "HashiCorp Vault",
			}).Info("Secret removed from source system, removing also from Vault")
			v.Client.KVv2(v.Engine).DeleteMetadata(context.Background(), cur.Name)
			removedSecrets++
		}
	}

	if removedSecrets > 0 {
		log.WithFields(log.Fields{
			"count":  removedSecrets,
			"system": "HashiCorp Vault",
		}).Info("Successfully cleaned removed secrets")
	}
}

// GetSecrets returns a Slice with all secrets from Vault which belong to env.
func (v *Vault) GetSecrets(env *secret.Environment) []*secret.Secret {
	if env == nil {
		env = &secret.GlobalEnv
	}

	var secrets []*secret.Secret

	for _, key := range v.getSecretKeys("") {
		s := v.getSecret(key)
		s.SetEnv()

		if s.BelongsToEnv(env) {
			if !env.IsGroup {
				s.TrimNameEnv()
			}
			secrets = append(secrets, s)
		}
	}

	log.WithFields(log.Fields{
		"count":  len(secrets),
		"system": "HashiCorp Vault",
	}).Info("Secrets successfully read")

	v.Secrets = append(v.Secrets, secrets...)

	return v.Secrets
}

// UpdateChangedSecrets compares each secret in newSecrets and curSecrets. If a secret has changed,
// data or metadata, it's updated to Vault. If a secret in curSecrets has been removed in
// newSecrets, it's removed from Vault.
func (v *Vault) UpdateChangedSecrets(newSecrets []*secret.Secret) {
	var updatedSecrets uint32
	var updateData bool
	var updateTags bool

	for _, new := range newSecrets {
		updateData = true
		updateTags = true

		for _, cur := range v.Secrets {
			if new.EqualName(cur) {
				updateData = !new.EqualData(cur)
				updateTags = !new.EqualTags(cur)
				break
			}
		}

		if updateData {
			v.putSecretData(new)
		}

		if updateTags {
			v.putSecretMetadata(new)
		}

		if updateData || updateTags {
			updatedSecrets++
		}
	}

	if updatedSecrets > 0 {
		log.WithFields(log.Fields{
			"count":  updatedSecrets,
			"system": "HashiCorp Vault",
		}).Info("Successfully created and/or updated secrets")
	} else {
		log.WithFields(log.Fields{
			"system": "HashiCorp Vault",
		}).Info("All secrets up to date")
	}
}

// UpdateSecrets compares new secrets to those currently in Vault, updating any changed and cleaning
// any removed.
func (v *Vault) UpdateSecrets(newSecrets []*secret.Secret) {
	v.GetSecrets(nil)
	v.UpdateChangedSecrets(newSecrets)
	v.CleanRemovedSecrets(newSecrets)
}

// createKvEngine creates a key-value Secrets Engine to Vault with given name.
func (v *Vault) createKvEngine(name string) {
	mountInfo := vault.MountInput{
		Type: "kv",
		Options: map[string]string{
			"version": "2",
		},
	}

	log.WithFields(log.Fields{
		"system": "HashiCorp Vault",
	}).Infof("Creating new kv Secrets Engine %s", name)

	if err := v.Client.Sys().Mount(name, &mountInfo); err != nil {
		log.WithFields(log.Fields{
			"secrets-engine": name,
			"system":         "HashiCorp Vault",
		}).WithError(err).Fatal("Secrets Engine creation failed")
	}
}

// getSecret returns data and metadata for secret in path.
func (v *Vault) getSecret(path string) *secret.Secret {
	secret := secret.New(path)

	vs, err := v.Client.KVv2(v.Engine).Get(context.Background(), secret.Name)
	if err != nil {
		log.WithFields(log.Fields{
			"path":   path,
			"system": "HashiCorp Vault",
		}).WithError(err).Error("Unable to read secret data")
	}

	secret.AddData(vs.Data)
	secret.AddTags(vs.CustomMetadata)

	return secret
}

// getSecretKeys returns a list of secret keys under given path.
func (v *Vault) getSecretKeys(path string) []string {
	var keys []string
	fullPath := v.Engine + "/metadata/" + path

	log.WithFields(log.Fields{
		"path":   fullPath,
		"system": "HashiCorp Vault",
	}).Debug("Retrieving secret keys")

	s, err := v.Client.Logical().List(fullPath)
	if err != nil {
		log.WithError(err).WithFields(log.Fields{
			"path":   fullPath,
			"system": "HashiCorp Vault",
		}).Fatal("Unable to list secret keys")
	}

	if s == nil {
		log.WithFields(log.Fields{
			"path":   fullPath,
			"system": "HashiCorp Vault",
		}).Warn("No secrets found")
		return keys
	}

	for _, data := range s.Data {
		keysInPath := helper.TransformToArray(data)
		for _, key := range keysInPath {
			if strings.HasSuffix(key, "/") {
				keys = append(keys, v.getSecretKeys(path+key)...)
			} else {
				keys = append(keys, path+key)
			}
		}
	}

	return keys
}

// hasEngine returns a boolean indicating whether a Secrets Engine with name already exists.
func (v *Vault) hasEngine(name string) bool {
	mounts, err := v.Client.Sys().ListMounts()
	if err != nil {
		log.WithFields(log.Fields{
			"system": "HashiCorp Vault",
		}).WithError(err).Fatal("Problem reading Secrets Engines")
	}

	for m := range mounts {
		// Mount (Secrets Engines) end in /-sign
		if m == name+"/" {
			return true
		}
	}

	return false
}

// putSecretData overwrites existing secret data or, if secret does not exist, creates new secret
// with data from secret.Data and empty metadata.
func (v *Vault) putSecretData(secret *secret.Secret) {
	_, err := v.Client.KVv2(v.Engine).Put(context.Background(), secret.Name, secret.Data)
	if err != nil {
		log.WithFields(log.Fields{
			"path":   secret.Name,
			"system": "HashiCorp Vault",
		}).WithError(err).Error("Unable to update secret data")
	}

	log.WithFields(log.Fields{
		"path":   secret.Name,
		"system": "HashiCorp Vault",
	}).Info("Succesfully put data to Vault secret")
}

// putSecretMetaadta overwrites existing secret metadadata or, if secret does not exist, creates
// new secret with metadata from secret.Tags and empty data.
func (v *Vault) putSecretMetadata(secret *secret.Secret) {
	metadata := vault.KVMetadataPutInput{CustomMetadata: secret.Tags}
	err := v.Client.KVv2(v.Engine).PutMetadata(context.Background(), secret.Name, metadata)
	if err != nil {
		log.WithFields(log.Fields{
			"path":   secret.Name,
			"system": "HashiCorp Vault",
		}).WithError(err).Error("Unable to update secret metadata")
	}

	log.WithFields(log.Fields{
		"path":   secret.Name,
		"system": "HashiCorp Vault",
	}).Info("Succesfully put metadata to Vault secret")
}
