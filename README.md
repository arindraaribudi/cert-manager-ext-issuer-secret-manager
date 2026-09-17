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