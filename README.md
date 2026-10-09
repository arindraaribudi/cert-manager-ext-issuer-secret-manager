# cert-manager-ext-issuer-secret-manager

External issuer for cert-manager that mirrors SSL certificates from AWS Secrets Manager, GCP Secret Manager, and Tencent SSL into Kubernetes Secret resources.

## CRDs

Secret-manager group `secret-manager.cert-manager.io/v1alpha1` (six kinds):

- `AWSSecretManagerIssuer` / `AWSSecretManagerClusterIssuer`
- `GCPSecretManagerIssuer` / `GCPSecretManagerClusterIssuer`
- `TencentSecretManagerIssuer` / `TencentSecretManagerClusterIssuer`

Certificate-download group `certificates.cert-manager.io/v1alpha1`
(mirror already-issued cloud certs into a k8s TLS Secret — see
[Certificate download](#certificate-download-acm--tencent-ssl) below):

- `AWSCertificateClusterIssuer` — AWS Certificate Manager
- `TencentCertificateClusterIssuer` — Tencent SSL

## Install

```bash
make codegen bundle
kubectl apply -f config/install.yaml
```

For per-file layout during development: `kubectl apply -f config/crd/bases/ -f config/rbac/role.yaml`.

## Build & verify

```bash
make codegen   # controller-gen: CRDs + deep-copy
make build     # ./bin/manager
make test      # go test ./...
make lint      # golangci-lint v2.13.2+
make audit     # govulncheck
make scan      # trivy HIGH,CRITICAL on built image

# offline Secret-from-keystore CLI (separate binary, see below)
go build -o bin/jks2secret ./cmd/jks2secret
```

Requires Go **1.27** and `golangci-lint` **v2.13.2+** (older builds can't
decode Go 1.27's export format).

## Sample (AWS)

```yaml
apiVersion: secret-manager.cert-manager.io/v1alpha1
kind: AWSSecretManagerIssuer
metadata:
  name: aws-prod
spec:
  region: us-east-1
  # secretRef optional — omit to use IRSA pod identity
---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: app-tls
  annotations:
    cert-manager.io/secret-manager-secret-name: my-app-cert
spec:
  secretName: app-tls-secret
  issuerRef:
    name: aws-prod
    group: secret-manager.cert-manager.io
    kind: AWSSecretManagerIssuer
```

The cloud-side secret should be JSON:
```json
{
  "certificate": "-----BEGIN CERTIFICATE-----...",
  "private_key": "-----BEGIN PRIVATE KEY-----...",
  "certificate_chain": "-----BEGIN CERTIFICATE-----..."
}
```
Keys are configurable per Issuer via `spec.payloadKeys`.

## Offline Secret generation (`jks2secret`)

Standalone CLI for producing the AWS Secrets Manager / GCP Secret
Manager JSON payload (the same `certificate` / `private_key` /
`certificate_chain` shape the controller reads from the cloud —
see [Sample (AWS)](#sample-aws) above) directly from an existing JKS
or PKCS#12 keystore. Useful for bootstrapping, migrations, and CI
pipelines that don't have a running controller. After writing the JSON
the tool re-parses every emitted PEM and cross-checks the certificate
set + private key against the source; it exits non-zero on any mismatch.

### Build

```bash
go build -o bin/jks2secret ./cmd/jks2secret
```

### Run

Keyed PKCS#12 source + keyless truststore (the typical bootstrap path —
source carries leaf+key, truststore carries the extra CAs the consumer
needs to verify the chain):

```bash
bin/jks2secret \
  -source tt/jks/esb-nonprod-user.p12 \
  -truststore tt/jks/client.truststore.jks \
  -password-file tt/jks/password \
  -out esb-nonprod-user-payload.json
```

Keyed source only (no truststore — the keystore already bundles every
CA the consumer needs):

```bash
bin/jks2secret \
  -source keystore.p12 \
  -password-file pw \
  -out payload.json
```

Truststore-only (no key — the payload gets `certificate` +
`certificate_chain` but no `private_key`):

```bash
bin/jks2secret \
  -source truststore.p12 \
  -password-file pw \
  -out trust-payload.json
```

Inline password (avoid in shell history; prefer `-password-file`):

```bash
bin/jks2secret -source keystore.p12 -password 's3cret' -out payload.json
```

Distinct truststore password (when it differs from the source password):

```bash
bin/jks2secret \
  -source source.p12 -password-file src.pw \
  -truststore trust.p12 -truststore-password-file trust.pw \
  -out payload.json
```

Pipe straight to the cloud (omit `-out` for stdout — no temp file, no
extra read):

```bash
# GCP Secret Manager
bin/jks2secret -source keystore.p12 -password-file pw \
  | gcloud secrets versions add my-cert --data-file=-

# AWS Secrets Manager
bin/jks2secret -source keystore.p12 -password-file pw \
  | aws secretsmanager put-secret-value \
      --secret-id my-cert --secret-string file:///dev/stdin
```

The source keystore is auto-detected: JKS first (`keystore-go`), then
PKCS#12 (`go-pkcs12`). `-truststore` is optional — drop it when the
keystore already carries every CA the consumer needs. Truststore-only
inputs are also supported (the payload gets `certificate` +
`certificate_chain` only, no `private_key`).

When `-truststore` is set, the tool unions the truststore CAs into
`certificate_chain`. The verify step then confirms every truststore CA
appears in the emitted chain:

```
source: leaf CN="esb-nonprod-user", 2 chain certs, key=1216 bytes PKCS#8
truststore: 2 unique CAs (0 new in addition to source chain)
verify: source + truststore ↔ generated match (leaf + 2 chain incl. 2 truststore CAs + key)
```

> **Cipher note:** `tt/jks/client.truststore.jks` is encrypted with
> `pbeWithSHA1And40BitRC2-CBC` (the legacy "strong encryption disabled"
> mode Java's `keytool` still tolerates). `go-pkcs12` refuses 40-bit
> RC2, so for that specific fixture the CLI can't open the truststore
> — re-export it with `keytool -importkeystore -srckeystore … -destkeystore … -deststoretype PKCS12`
> to get a cipher `go-pkcs12` supports.

### Flags

| flag | description |
| --- | --- |
| `-source` | path to source JKS or PKCS#12 (required) |
| `-truststore` | optional: path to a JKS / PKCS#12 truststore whose CAs are unioned into `certificate_chain` |
| `-password` / `-password-file` | `-source` password (one of them required) |
| `-truststore-password` / `-truststore-password-file` | `-truststore` password (defaults to `-source` password when `-truststore` is set) |
| `-out` | output JSON path; omit for stdout |
| `-skip-verify` | skip source-vs-generated cross-check (not recommended) |

### Output

The JSON payload matches the cloud-side shape the controller reads:

```json
{
  "certificate": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n",
  "private_key": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n",
  "certificate_chain": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n"
}
```

- `certificate` — the leaf only.
- `private_key` — PKCS#8 PEM. Absent for truststore-only inputs.
- `certificate_chain` — CA bundle only (no leaf duplication).

The verify step logs the source fingerprint set and confirms it matches
the generated payload:

```
source: leaf CN="esb-nonprod-user", 2 chain certs, key=1216 bytes PKCS#8
wrote esb-nonprod-user-payload.json (4266 bytes)
verify: source fingerprint set: [a9f1a2bba96b d4f9d4b12923 f3d4955c38d8]
verify: source ↔ generated match (leaf + 2 chain + key)
```

Upload the JSON to your cloud secret store and reference it from an
Issuer / Certificate as shown in [Sample (AWS)](#sample-aws).

## Certificate download (ACM / Tencent SSL)

A separate CRD group — `certificates.cert-manager.io/v1alpha1` — mirrors
already-issued certs from a cloud CA into a k8s TLS Secret. Out-of-band
issuance (you control the cert lifecycle in the cloud), the controller
just downloads and mirrors.

### AWS ACM

```yaml
apiVersion: certificates.cert-manager.io/v1alpha1
kind: AWSCertificateClusterIssuer
metadata:
  name: prod-acm
spec:
  region: us-east-1
  # secretRef optional — omit for IRSA pod identity.
  # Keys: access-key-id, secret-access-key [, session-token, passphrase]
  secretRef:
    name: aws-creds
    namespace: cert-manager
```

Annotate the `Certificate` with the ACM ARN:

```yaml
metadata:
  annotations:
    acm.cert-manager.io/certificate-arn: arn:aws:acm:us-east-1:111122223333:certificate/abc
spec:
  secretName: app-tls-secret
  issuerRef:
    name: prod-acm
    group: certificates.cert-manager.io
    kind: AWSCertificateClusterIssuer
```

Private-key export from ACM requires a `passphrase` key in the same k8s
Secret. Public certs skip the decrypt path automatically. ACM public
certs issued before 2025-06-17 cannot be exported — `DescribeFailed`
will surface this.

### Tencent SSL

```yaml
apiVersion: certificates.cert-manager.io/v1alpha1
kind: TencentCertificateClusterIssuer
metadata:
  name: prod-ssl
spec:
  region: ap-hongkong
  # secretRef optional — omit for TKE OIDC / CVM metadata chain.
  # Keys: secret-id, secret-key
  secretRef:
    name: tc-creds
    namespace: cert-manager
```

```yaml
metadata:
  annotations:
    tencent.cert-manager.io/certificate-id: AbCdEf123
```

## Documentation

See [docs/FEATURE.md](docs/FEATURE.md) for the component diagram, install
guide, RBAC, full deployment manifest, and sample Issuer + Certificate resources
for every supported provider.