# Secrets Synchronizing

This repository contains resources for a tool synchronizing secrets between the source and
destination system. These systems can be AWS Secrets Manager or HashiCorp Vault.

This documentation has two parts: _How it Works_ and _How it's Used_. Both sections' contents are
hopefully self-explanatory.

## How it Works

### Configuration

The tool reads all<sup>1</sup> configuration from environment variables.

As both source and destinaton systems can be same, such as Vault, and both systems could require
different configurations, they _can_ be singled out by prefixing environmental variables with
`SOURCE_` and `DEST_`. If no prefix is applied, the configuration will be read by all systems which
it concerns.

For example, when configuring `VAULT_ADDR`, it will be applied to all Vault instances by default. If
you would want to target the "destination" Vault specifically, the environment variable would be
`DEST_VAULT_ADDR`.

From AWS' perspective, a role is required with enough permissions to read secrets from Secrets
Manager. This role will be assumed by the tool (`AWS_ROLE_ARN` configuration variable, see below).

The secret-sync application does not define how applications would access the secrets synchronized
to Vault. It's only job is to synchronize these secrets between a source system and a destination
system.

<sup>1</sup> Some configurations, such as AWS credentials, can be read from other places if so
documented by the SDK developer.

#### General Configuration Variables

| Name                   | Required | Default | Description                                               |
|------------------------|----------|---------|-----------------------------------------------------------|
| `LOG_LEVEL`            | false    | info    | Sets logging level: debug, info, warn, error, or fatal.   |
| `DEST_SYSTEM`          | true     |         | System type secrets are synced to: `vault`.               |
| `ENVIRONMENT`          | true     |         | Sync environment. For options and description, see below. |
| `SOURCE_SYSTEM`        | true     |         | System type secrets are synced from: `aws` or `vault`.    |

#### AWS Configuration Variables

| Name           | Required | Default      | Description                              |
|----------------|----------|--------------|------------------------------------------|
| `AWS_REGION`   | false    | eu-central-1 | AWS region to retrieve the secrets from. |
| `AWS_ROLE_ARN` | false    | _no role_    | ARN of the AWS role to assume.           |

#### Vault Configuration Variables

| Name                    | Required         | Default | Description                                |
|-------------------------|------------------|---------|--------------------------------------------|
| `VAULT_ADDR`            | true             |         | Base URL of the HashiCorp Vault instance.  |
| `VAULT_SECRETS_ENGINE`  | false            | secrets | Secrets engine from/to which sync secrets. |
| `VAULT_KUBERNETES_ROLE` | true<sup>2</sup> |         | Vault Kubernetes used for authentication.  |
| `VAULT_TOKEN`           | true<sup>2</sup> |         | Vault authentication token.                |

<sup>2</sup> Either `VAULT_KUBERNETES_ROLE` or `VAULT_TOKEN` is required.

All environment variables listed in Vault Go-packages
[documentation](https://pkg.go.dev/github.com/hashicorp/vault/api#pkg-constants) and AWS SDK are
valid and usable<sup>3</sup>.

<sup>3</sup> Variables not defined in the modules will be applied to all instances to which it
concerns. (For example, if both source and destination systems are Vault instances and
VAULT_SKIP_VERIFY is set, the config will be read by both instances.)

### Secrets and Environments

The tools supports syncing environment specific secrets by default. Each environment can have a
different value for same secret. This is supported by appending the environment in the secret's name
(separated by dash (`-`)). So if you'd want to have the secret `apps/my-python-app/db-password` to
have a certain value in `dev`, and a different value in `test`, simply name them
`apps/my-python-app/db-password-dev` and `apps/my-python-app/db-password-test`, respectively.
Alternatively, you can use `Environment` tag/ metadata entry to indicate the environment.

**The environment will be removed from secret's name when syncing secrets to given environment's secret manager.**
This means that you can still use the `apps/my-python-app/db-password` as a reference in your app in
both of the environments.

Supported environments are listed below. When using a group decorator, the secret will be synced to
all environments included in the given group.

| Environment | Desciption                                      |
|-------------|-------------------------------------------------|
| `dev`       | Development environment.                        |
| `test`      | Test environment.                               |
| `staging`   | Staging environment.                            |
| `prod`      | Production environment.                         |
| `nonprod`   | Group including all environments except `prod`. |
| `global`    | Group including all environments.               |

### Synchronizing by Environment

To limit which secrets are synchronized from the source system, the tool uses two ways to identify
correct resources: secret name suffix (e.g. my-secret-prod) and the `Environment` tag/ metadata
entry. Only secrets which "belong" to given configured environment are synced. If secret has no
environment defined, it will not be synced.

A secret belongs to a sync environment if its environment is set, and if it fulfils any of the
following rules:

1. Secret's environment is the same as sync environment.
1. Secret's or sync environment is defined as `global`.
1. Secret's or sync environment is defined as `nonprod` and the other is not `prod`.

## How it's Used

_How it's Used_ covers secret syncing in the development platform scale. This means the
documentation is not tied to a specific _secret-sync_ instance, but covers secrets in the whole
platform.

From a user's perspective, all that it's initially required is access to an AWS account with a role
that has enough permissions to crete secrets in the Secrets Manager. Then, the idea would be to add
a secret to any source system (e.g. AWS Secrets Manager) and wait for it to be synchronized across
the cluster of destination systems (one per secrets-sync instance, as it does not support
one-to-many synchronizations). This naturally requires for the secret-sync to be scheduled on a
periodical execution.
