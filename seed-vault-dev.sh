#!/bin/sh
# Seed an empty Vault dev server with safe fake data for vaultui-py.py.
# Заполняет пустой Vault dev безопасными тестовыми данными для vaultui-py.py.

set -eu

VAULT_ADDR="${VAULT_ADDR:-http://127.0.0.1:8200}"
VAULT_TOKEN="${VAULT_TOKEN:-root}"
export VAULT_ADDR VAULT_TOKEN

log() {
  # EN: Keep seed output readable and grep-friendly.
  # RU: Держим вывод seed читаемым и удобным для grep.
  printf '%s\n' "==> $*"
}

warn() {
  # EN: Warnings go to stderr so scripts can separate status from data.
  # RU: Warnings пишутся в stderr, чтобы скрипты отделяли статус от данных.
  printf '%s\n' "WARN: $*" >&2
}

have_mount() {
  # EN: Idempotency check for secret engines.
  # RU: Проверка идемпотентности для secret engines.
  vault secrets list -format=json | grep -q "\"$1/\""
}

have_auth() {
  # EN: Idempotency check for auth methods.
  # RU: Проверка идемпотентности для auth methods.
  vault auth list -format=json | grep -q "\"$1/\""
}

enable_secret_engine() {
  # EN: Enable a secret engine only when it is missing.
  # RU: Включаем secret engine только если он ещё не существует.
  path="$1"
  type="$2"
  shift 2
  if have_mount "$path"; then
    log "secret engine already enabled: $path/"
    return 0
  fi
  log "enabling secret engine: $path/ ($type)"
  vault secrets enable "$@" -path="$path" "$type" >/dev/null
}

enable_auth_method() {
  # EN: Enable an auth method only when it is missing.
  # RU: Включаем auth method только если он ещё не существует.
  path="$1"
  type="$2"
  shift 2
  if have_auth "$path"; then
    log "auth method already enabled: $path/"
    return 0
  fi
  log "enabling auth method: $path/ ($type)"
  vault auth enable "$@" -path="$path" "$type" >/dev/null
}

log "using VAULT_ADDR=$VAULT_ADDR"

if ! vault status >/dev/null 2>&1; then
  warn "Vault is not reachable. Start it first, for example:"
  warn "  vault server -dev -dev-root-token-id=root"
  exit 1
fi

if ! have_mount secret; then
  enable_secret_engine secret kv -version=2
fi

log "writing KV v2 application secrets with version history"
vault kv put secret/apps/myapp/config \
  db_host=fake-db.test.internal \
  db_port=5432 \
  db_name=testdb \
  db_user=testuser \
  db_password=FAKE-password-v1-do-not-use >/dev/null

vault kv put secret/apps/myapp/config \
  db_host=fake-db.test.internal \
  db_port=5432 \
  db_name=testdb \
  db_user=testuser \
  db_password=FAKE-password-v2-do-not-use \
  log_level=info >/dev/null

vault kv put secret/apps/myapp/config \
  db_host=fake-db.test.internal \
  db_port=5432 \
  db_user=testuser \
  db_password=FAKE-password-v2-do-not-use \
  log_level=debug \
  api_endpoint=https://api.test.example.com/v2 >/dev/null

vault kv put secret/apps/myapp/database \
  connection_url="postgresql://fake-db.test.internal:5432/testdb" \
  username=test-admin \
  password=FAKE-hunter2-not-real >/dev/null

vault kv put secret/apps/myapp/api-keys \
  stripe_key=sk_test_FAKE_000000000000000000000000 \
  sendgrid_key=SG.FAKE_TEST_KEY_000000000000 >/dev/null

vault kv put secret/apps/billing/config \
  api_url=https://billing.test.example.com \
  timeout=30s \
  webhook_secret=whsec_FAKE_test_000000000000 >/dev/null

CERT=$(printf '%s\n' \
  '-----BEGIN CERTIFICATE-----' \
  'FAKE-TEST-CERT-DO-NOT-USE-IN-PRODUCTION' \
  'MIIFazCCA1OgAwIBAgIUEJzGFMHhKLkjSbGBbCOIZmQDM3owDQYJKoZIhvcNAQEL' \
  'BQAwRTELMAkGA1UEBhMCVVMxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM' \
  'GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yNTAxMDEwMDAwMDBaFw0yNjAx' \
  'MDEwMDAwMDBaMEUxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw' \
  '-----END CERTIFICATE-----')

PKEY=$(printf '%s\n' \
  '-----BEGIN RSA PRIVATE KEY-----' \
  'FAKE-TEST-KEY-DO-NOT-USE-IN-PRODUCTION' \
  'MIIEowIBAAKCAQEA2a2rwplBQLfBCW1OZMM1RqRFHGFLMND/TjKDMp1NFQT9XGBx' \
  'Xm/K3FYPbLdGKyNBCMzjQbNOIwJce2fCMNHVMk+YHaGFMI3bMGdWPGT5MBM0XzW' \
  'wJ4c1M5y3H8E7LqB4AkFPQa3igNprWHDflAeB3Y2PWMZR8rOaYEMQm1zKHPXLF0' \
  '-----END RSA PRIVATE KEY-----')

vault kv put secret/infra/tls/wildcard cert="$CERT" key="$PKEY" >/dev/null
vault kv put secret/infra/aws \
  access_key=AKIAEXAMPLE000TEST00 \
  secret_key=FAKE/TestSecretKey+DO+NOT+USE+IN+PRODUCTION0 >/dev/null
vault kv put secret/infra/ssh/deploy-key \
  public_key="ssh-rsa AAAAB3NzaFAKETESTKEY000000000000 test-deploy@fake-host" \
  private_key="FAKE-OPENSSH-PRIVATE-KEY-DO-NOT-USE" >/dev/null

log "writing ACL policies"
vault policy write base-read - >/dev/null <<'POLICY'
path "sys/mounts" {
  capabilities = ["read"]
}
path "sys/auth" {
  capabilities = ["read"]
}
path "sys/policies/acl" {
  capabilities = ["read", "list"]
}
path "sys/policies/acl/*" {
  capabilities = ["read"]
}
path "sys/health" {
  capabilities = ["read"]
}
path "secret/metadata" {
  capabilities = ["list"]
}
path "secret/metadata/*" {
  capabilities = ["list"]
}
POLICY

vault policy write app-secrets - >/dev/null <<'POLICY'
path "secret/data/apps/*" {
  capabilities = ["read"]
}
path "secret/metadata/apps/*" {
  capabilities = ["list"]
}
POLICY

vault policy write infra-secrets - >/dev/null <<'POLICY'
path "secret/data/infra/*" {
  capabilities = ["read"]
}
path "secret/metadata/infra/*" {
  capabilities = ["list"]
}
POLICY

vault policy write admin - >/dev/null <<'POLICY'
path "*" {
  capabilities = ["create", "read", "update", "delete", "list", "sudo"]
}
POLICY

log "configuring auth methods"
enable_auth_method userpass userpass
vault write auth/userpass/users/testuser \
  password=testpass \
  policies=base-read,app-secrets >/dev/null

enable_auth_method approle approle
vault write auth/approle/role/test-role \
  token_ttl=1h \
  token_max_ttl=4h \
  policies=base-read,infra-secrets >/dev/null
ROLE_ID=$(vault read -field=role_id auth/approle/role/test-role/role-id)
SECRET_ID=$(vault write -field=secret_id -f auth/approle/role/test-role/secret-id)

enable_auth_method ldap ldap -description="LDAP auth (unconfigured test mount)"

log "creating identity entities and groups"
vault write identity/entity/name/test-user-entity policies=base-read,app-secrets >/dev/null
vault write identity/entity/name/admin-entity policies=admin >/dev/null
vault write identity/group/name/dev-team policies=base-read,app-secrets type=internal >/dev/null
vault write identity/group/name/ops-team policies=admin type=internal >/dev/null

log "configuring PKI"
enable_secret_engine pki pki
vault secrets tune -max-lease-ttl=87600h pki/ >/dev/null
vault write pki/root/generate/internal \
  common_name="Test Root CA" \
  ttl=87600h >/dev/null
vault write pki/roles/test-role \
  allowed_domains="test.example.com" \
  allow_subdomains=true \
  max_ttl=72h >/dev/null
vault write pki/issue/test-role \
  common_name="app1.test.example.com" \
  ttl=24h >/dev/null

log "configuring Transit"
enable_secret_engine transit transit
vault write -f transit/keys/my-app-key >/dev/null
vault write -f transit/keys/payment-key type=aes256-gcm96 >/dev/null

log "configuring Database engine with fake offline connection"
# EN: verify_connection=false lets a plain dev Vault expose DB config/roles
#     without requiring a running PostgreSQL server.
# RU: verify_connection=false позволяет обычному dev Vault показать DB config/roles
#     без запущенного PostgreSQL.
enable_secret_engine database database
vault write database/config/testdb-postgres \
  plugin_name=postgresql-database-plugin \
  allowed_roles="app-readwrite,app-readonly,analyst,ops-monitoring" \
  connection_url="postgresql://{{username}}:{{password}}@127.0.0.1:5432/testdb?sslmode=disable" \
  username="postgres" \
  password="postgres" \
  verify_connection=false >/dev/null

vault write database/roles/app-readwrite \
  db_name=testdb-postgres \
  creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';" \
  revocation_statements="DROP ROLE IF EXISTS \"{{name}}\";" \
  default_ttl=1h \
  max_ttl=24h >/dev/null

vault write database/roles/app-readonly \
  db_name=testdb-postgres \
  creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';" \
  revocation_statements="DROP ROLE IF EXISTS \"{{name}}\";" \
  default_ttl=1h \
  max_ttl=12h >/dev/null

vault write database/roles/analyst \
  db_name=testdb-postgres \
  creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';" \
  default_ttl=30m \
  max_ttl=4h >/dev/null

if vault write database/static-roles/ops-monitoring \
  db_name=testdb-postgres \
  username="postgres" \
  rotation_period=86400 \
  rotation_statements="ALTER USER \"{{name}}\" WITH PASSWORD '{{password}}';" >/dev/null 2>&1; then
  log "database static role created"
else
  warn "database static role skipped; this Vault build may validate offline DB rotation"
fi

log "configuring AWS engine with fake offline settings"
# EN: AWS config points at localhost so roles are browsable without LocalStack.
# RU: AWS config смотрит на localhost, чтобы роли можно было просматривать без LocalStack.
enable_secret_engine aws aws
vault write aws/config/root \
  access_key=test \
  secret_key=test \
  region=us-east-1 \
  iam_endpoint=http://127.0.0.1:4566 \
  sts_endpoint=http://127.0.0.1:4566 >/dev/null

vault write aws/config/lease lease=30m lease_max=1h >/dev/null

vault write aws/roles/deploy-iam-user \
  credential_type=iam_user \
  policy_arns="arn:aws:iam::aws:policy/ReadOnlyAccess" >/dev/null

vault write aws/roles/ci-assumed-role \
  credential_type=assumed_role \
  role_arns="arn:aws:iam::000000000000:role/ci-role" \
  default_sts_ttl=1800 \
  max_sts_ttl=3600 >/dev/null

vault write aws/roles/readonly-federation \
  credential_type=federation_token \
  policy_document='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject","s3:ListBucket"],"Resource":"*"}]}' \
  default_sts_ttl=900 \
  max_sts_ttl=3600 >/dev/null

cat <<EOF

Seed data loaded successfully.

Useful test credentials:
  userpass: username=testuser password=testpass
  approle:  role_id=$ROLE_ID
            secret_id=$SECRET_ID

Run:
  VAULT_ADDR=$VAULT_ADDR VAULT_TOKEN=$VAULT_TOKEN ./vaultui-py.py
EOF
