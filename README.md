# cert-manager-ext-issuer-secret-manager

External issuer for cert-manager that mirrors SSL certificates from AWS Secrets Manager, GCP Secret Manager, and Tencent SSL into Kubernetes Secret resources.

## CRDs

All kinds share the `secret-manager.cert-manager.io/v1alpha1` group:

- `AWSSecretManagerIssuer` / `AWSSecretManagerClusterIssuer`
- `GCPSecretManagerIssuer` / `GCPSecretManagerClusterIssuer`
- `TencentSecretManagerIssuer` / `TencentSecretManagerClusterIssuer`

## Install

```bash
make codegen bundle
kubectl apply -f config/install.yaml
```

For per-file layout during development: `kubectl apply -f config/crd/bases/ -f config/rbac/role.yaml`.

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

## Documentation

See [docs/COMPONENTS.md](docs/COMPONENTS.md) for the component diagram, install
guide, RBAC, full deployment manifest, and sample Issuer + Certificate resources
for every supported provider.