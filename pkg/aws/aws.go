package aws

import (
	"encoding/json"
	"sync-secrets/pkg/helper"
	"sync-secrets/pkg/secret"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	log "github.com/sirupsen/logrus"
)

const (
	EnvRegion  = "AWS_REGION"
	EnvRoleArn = "AWS_ROLE_ARN"

	DefaultRegion = "eu-central-1"
)

type SecretsManager struct {
	Config  *aws.Config
	Client  *secretsmanager.SecretsManager
	Region  string
	RoleArn string
}

// New returns a new SecretsManager struct. Configurations are read from environment variables. The
// envPrefix is used to check for non-generic configs (used as a prefix for the variables), as more
// SecretsManagers could be configured for the same session. Any generic variable is also checked if
// prefixed option does not exist.
//
// For example, New("SOURCE_") will first get value from "SOURCE_AWS_REGION". If not found, tries to
// get value from "AWS_REGION".
func New(envPrefix string) *SecretsManager {
	s := SecretsManager{}

	if e := helper.Getenv(envPrefix, EnvRegion); e != "" {
		s.Region = e
	} else {
		s.Region = DefaultRegion
	}

	if e := helper.Getenv(envPrefix, EnvRoleArn); e != "" {
		s.RoleArn = e
	}

	sess := session.Must(session.NewSession())
	config := aws.Config{}
	fields := log.Fields{"system": "AWS Secrets Manager"}

	config.Region = &s.Region
	fields["region"] = s.Region

	if s.RoleArn != "" {
		config.Credentials = stscreds.NewCredentials(sess, s.RoleArn)
		fields["role"] = s.RoleArn
	}

	s.Config = &config
	s.Client = secretsmanager.New(sess, &config)

	if _, err := sess.Config.Credentials.Get(); err != nil {
		log.WithFields(fields).WithError(err).Fatal("Failed to create AWS session")
	}

	log.WithFields(fields).Info("AWS session created successfully")

	return &s
}

// GetSecrets returns a Slice with all secrets from Secrets Manager which belong to env.
func (m *SecretsManager) GetSecrets(env *secret.Environment) []*secret.Secret {
	if env == nil {
		env = &secret.GlobalEnv
	}

	var secrets []*secret.Secret

	input := &secretsmanager.ListSecretsInput{}
	for _, awsSecret := range m.ListSecrets(input) {
		s := secret.New(aws.StringValue(awsSecret.Name))
		data := aws.StringValue(m.getSecretValue(awsSecret.ARN).SecretString)

		// Transform [{"Key": "tag-key", "Value": "tag-value"}] to {"tag-key": "tag-value"}
		for _, awsTag := range awsSecret.Tags {
			s.Tags[aws.StringValue(awsTag.Key)] = aws.StringValue(awsTag.Value)
		}

		json.Unmarshal([]byte(data), &s.Data)
		s.SetEnv()

		if s.BelongsToEnv(env) {
			if !env.IsGroup {
				s.TrimNameEnv()
			}
			secrets = append(secrets, s)
			log.WithFields(log.Fields{
				"system": "AWS Secrets Manager",
			}).Debugf("Retrieving secret %s", s.Name)
		} else {
			log.WithFields(log.Fields{
				"system": "AWS Secrets Manager",
			}).Debugf("Ignoring secret %s", s.Name)
		}
	}

	log.WithFields(log.Fields{
		"count":  len(secrets),
		"system": "AWS Secrets Manager",
	}).Info("Secrets successfully read")

	return secrets
}

// ListSecrets is a wrapper around AWS SDK's SecretsManager.ListSecrets()-function. Handles errors
// and returns a SecretsManager.ListSecretsOutput.
func (m *SecretsManager) ListSecrets(input *secretsmanager.ListSecretsInput) []*secretsmanager.SecretListEntry {
	var secrets []*secretsmanager.SecretListEntry
	output, err := m.Client.ListSecrets(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case secretsmanager.ErrCodeInvalidParameterException:
				log.Error(secretsmanager.ErrCodeInvalidParameterException, aerr.Error())
			case secretsmanager.ErrCodeInvalidNextTokenException:
				log.Error(secretsmanager.ErrCodeInvalidNextTokenException, aerr.Error())
			case secretsmanager.ErrCodeInternalServiceError:
				log.Error(secretsmanager.ErrCodeInternalServiceError, aerr.Error())
			default:
				log.WithFields(log.Fields{
					"system": "AWS Secrets Manager",
				}).WithError(err).Fatal("Failed to list secrets")
			}
		} else {
			log.WithFields(log.Fields{
				"system": "AWS Secrets Manager",
			}).WithError(err).Fatal("Unknown error while listing secrets")
		}

		return nil
	}

	secrets = append(secrets, output.SecretList...)

	if output.NextToken != nil {
		input.SetNextToken(*output.NextToken)
		secrets = append(secrets, m.ListSecrets(input)...)
	}

	return secrets
}

// getSecretValue is a wrapper around AWS SDK's SecretsManager.GetSecretValue()-function. Handles
// errors and returns a SecretsManager.GetSecretValueOutput.
func (m *SecretsManager) getSecretValue(arn *string) *secretsmanager.GetSecretValueOutput {
	input := &secretsmanager.GetSecretValueInput{
		SecretId: arn,
	}

	secret, err := m.Client.GetSecretValue(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case secretsmanager.ErrCodeResourceNotFoundException:
				log.Error(secretsmanager.ErrCodeResourceNotFoundException, aerr.Error())
			case secretsmanager.ErrCodeInvalidParameterException:
				log.Error(secretsmanager.ErrCodeInvalidParameterException, aerr.Error())
			case secretsmanager.ErrCodeInvalidRequestException:
				log.Error(secretsmanager.ErrCodeInvalidRequestException, aerr.Error())
			case secretsmanager.ErrCodeDecryptionFailure:
				log.Error(secretsmanager.ErrCodeDecryptionFailure, aerr.Error())
			case secretsmanager.ErrCodeInternalServiceError:
				log.Error(secretsmanager.ErrCodeInternalServiceError, aerr.Error())
			default:
				log.WithFields(log.Fields{
					"system": "AWS Secrets Manager",
				}).WithError(err).Error("Failed to get secret value")
			}
		} else {
			log.WithFields(log.Fields{
				"system": "AWS Secrets Manager",
			}).WithError(err).Error("Unknown error while retrieving secret value")
		}

		return nil
	}

	return secret
}
