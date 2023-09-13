package main

import (
	"os"
	"sync-secrets/pkg/aws"
	"sync-secrets/pkg/secret"
	"sync-secrets/pkg/vault"

	log "github.com/sirupsen/logrus"
)

const (
	PrefixDest   = "DEST_"
	PrefixSource = "SOURCE_"

	EnvLogLevel = "LOG_LEVEL"
	EnvSyncEnv  = "ENVIRONMENT"
	EnvSystem   = "SYSTEM"

	SystemAws   = "aws"
	SystemVault = "vault"
)

var SyncEnv secret.Environment

func init() {
	SetLogLevel()
	SetEnvironment()
}

func main() {
	secrets := GetSourceSecrets()
	UpdateDestinationSecrets(secrets)
}

// SetEnvironment reads the sync environment from environment variable and sets SyncEnv as correct
// secret.Environment.
func SetEnvironment() {
	if v := os.Getenv(EnvSyncEnv); v != "" {
		if e := secret.GetEnvFromString(v); e != nil {
			SyncEnv = *e
		} else {
			log.Fatalf("%s not accepted value for %s", e, EnvSyncEnv)
		}
	} else {
		log.Fatalf("Required env variable %s not defined", EnvSyncEnv)
	}
}

// SetLogLevel reads desired logging level from the LOG_LEVEL env variable and sets it. Possible
// options are debug, info, warn, error, fatal, and panic. Defaults to logrus's default.
func SetLogLevel() {
	var envLogLevel string

	if v := os.Getenv(EnvLogLevel); v != "" {
		envLogLevel = v
	}

	switch envLogLevel {
	case "debug":
		log.SetLevel(log.DebugLevel)
	case "info":
		log.SetLevel(log.InfoLevel)
	case "warn":
		log.SetLevel(log.WarnLevel)
	case "error":
		log.SetLevel(log.ErrorLevel)
	case "fatal":
		log.SetLevel(log.FatalLevel)
	}
}

// GetSourceSecrets returns a Slice of secrets from the source system.
func GetSourceSecrets() []*secret.Secret {
	var system string
	prefix := PrefixSource

	if v := os.Getenv(prefix + EnvSystem); v != "" {
		system = v
	} else {
		log.Fatalf("Required env variable %s not defined", prefix+EnvSystem)
	}

	switch system {
	case SystemAws:
		a := aws.New(prefix)
		return a.GetSecrets(&SyncEnv)

	case SystemVault:
		v := vault.New(prefix)
		return v.GetSecrets(&SyncEnv)

	default:
		log.Fatalf("%s should be one of: %s, %s", prefix+EnvSystem, SystemAws, SystemVault)
		return nil // Will not execute
	}
}

// UpdateDestinationSecrets sets secrets into the destination system.
func UpdateDestinationSecrets(secrets []*secret.Secret) {
	var system string
	prefix := PrefixDest

	if v := os.Getenv(prefix + EnvSystem); v != "" {
		system = v
	} else {
		log.Fatalf("Required env variable %s not defined", prefix+EnvSystem)
	}

	switch system {
	case SystemVault:
		v := vault.New(prefix)
		v.UpdateSecrets(secrets)

	default:
		log.Fatalf("%s should be one of: %s", prefix+EnvSystem, SystemVault)
	}
}
