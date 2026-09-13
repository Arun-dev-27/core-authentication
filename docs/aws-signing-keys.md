# RS256 signing keys on AWS — private keys in Secrets Manager, public keys via JWKS

| What | Where | Who can read |
|---|---|---|
| **Private keys** (PKCS#8 PEM) | **AWS Secrets Manager** secret (KMS customer-managed key) — or SSM Parameter Store as an alternative | Identity Federation pods only (IRSA) |
| **Public keys** | `GET https://identity.miqaat.com/.well-known/jwks.json` (`kty n e kid alg use` only) | Everyone — every BU verifies with it |
| Key metadata (`kid`, status, thumbprint) | Authentication DB `signing_key_metadata` | Identity Federation |

Private keys are never stored in PostgreSQL, source control, images, ConfigMaps or logs, and never shared with Business Units.
Production configuration refuses the `file` provider and any `AWS_ENDPOINT_URL` override.

## Secrets Manager (recommended)

```
SIGNING_KEY_PROVIDER=secretsmanager
SECRETS_MANAGER_SIGNING_KEYS_SECRET_ID=miqaat/identity/prod/signing-keys
SIGNING_KEYS_KMS_KEY_ID=arn:aws:kms:<REGION>:<ACCOUNT_ID>:key/<CMK_ID>
AWS_REGION=ap-south-1
KEY_REFRESH_INTERVAL_SECONDS=300
```

One secret holds the whole keyset:

```json
{
  "keys": [
    { "kid": "miqaat-key-2026-09-a1b2c3", "alg": "RS256", "status": "ACTIVE",
      "createdAt": "2026-09-13T10:00:00.000Z", "activatedAt": "2026-09-13T10:00:00.000Z",
      "privateKeyPem": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n" }
  ]
}
```

Every rotation step (`generate`, `stage`, `promote`, `retire`) writes a **new secret version** (`AWSCURRENT`);
the previous keyset stays available as `AWSPREVIOUS` for audit and emergency rollback. Pods reload the secret every
`KEY_REFRESH_INTERVAL_SECONDS` and keep the last known-good keyset if a reload fails.

### IAM — runtime role (IRSA on the Identity Federation service account)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    { "Effect": "Allow", "Action": "secretsmanager:GetSecretValue",
      "Resource": "arn:aws:secretsmanager:<REGION>:<ACCOUNT_ID>:secret:miqaat/identity/prod/signing-keys-*" },
    { "Effect": "Allow", "Action": "kms:Decrypt", "Resource": "arn:aws:kms:<REGION>:<ACCOUNT_ID>:key/<CMK_ID>",
      "Condition": { "StringEquals": { "kms:ViaService": "secretsmanager.<REGION>.amazonaws.com" } } }
  ]
}
```

### IAM — rotation role (CI job / break-glass; never the pods)

`secretsmanager:GetSecretValue`, `secretsmanager:PutSecretValue`, `secretsmanager:CreateSecret` (bootstrap) on the
secret, plus `kms:Encrypt`, `kms:GenerateDataKey`, `kms:Decrypt` on the CMK.

### Resource policy on the secret (deny everyone else)

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Deny", "Principal": "*", "Action": "secretsmanager:GetSecretValue", "Resource": "*",
    "Condition": { "ArnNotEquals": { "aws:PrincipalArn": [
      "arn:aws:iam::<ACCOUNT_ID>:role/miqaat-identity-federation-prod",
      "arn:aws:iam::<ACCOUNT_ID>:role/miqaat-identity-key-rotation" ] } }
  }]
}
```

Enable CloudTrail data events for the secret and alarm on any `GetSecretValue` from unexpected principals.

## Rotation runbook

```bash
# rotation role credentials; same env as the service (SIGNING_KEY_PROVIDER=secretsmanager)
npm run keys:rotate -- status
npm run keys:rotate -- stage      # NEXT key added and published in JWKS (not yet signing)
# wait >= KEY_REFRESH_INTERVAL_SECONDS (300) + BU JWKS cache (600): ~20 minutes
npm run keys:rotate -- promote    # NEXT -> ACTIVE (new kid signs), ACTIVE -> RETIRING (still in JWKS)
# wait >= 1 hour (assertions live 60 s; generous margin for clock skew and caches)
npm run keys:rotate -- retire     # RETIRING -> RETIRED (removed from JWKS)
```

Bootstrap a new environment: `npm run keys:generate` (one ACTIVE 3072-bit RSA key; creates the secret).

**Compromised key**: `stage` + `promote` immediately, `retire -- --min-retiring-seconds 0`, then force federation
logout (`POST /federation/logout` with the admin bearer) for affected users.

## Local development

`docker compose up -d` starts LocalStack (Secrets Manager) on `:4566`; `.env` sets `AWS_ENDPOINT_URL=http://localhost:4566`
with dummy credentials, so the service loads keys through the same AWS SDK path as production. Verified by
`test/e2e/secrets-manager-keys.e2e-spec.ts` (secret creation, versioning on rotation, service boot, JWKS contents,
assertion verification).

## SSM Parameter Store (alternative)

`SIGNING_KEY_PROVIDER=ssm`, `SSM_SIGNING_KEYS_PATH=/miqaat/identity/prod/signing-keys` — one SecureString (Advanced tier,
CMK) per key at `<path>/<kid>`. Runtime IAM: `ssm:GetParametersByPath` on the path + `kms:Decrypt`; rotation adds
`ssm:PutParameter`.
