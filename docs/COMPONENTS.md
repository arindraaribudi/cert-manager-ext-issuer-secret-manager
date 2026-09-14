# Components

External issuer for [cert-manager](https://cert-manager.io) that mirrors TLS material
from cloud secret stores (AWS Secrets Manager, GCP Secret Manager, Tencent SSL)
into a Kubernetes `Secret` of type `kubernetes.io/tls`. The controller watches
`cert-manager.io/v1` `Certificate` resources whose `issuerRef` points at one of
the six CRDs in the `secret-manager.cert-manager.io/v1alpha1` group.

## Component diagram

```mermaid
flowchart LR
    User([User / GitOps]) -->|kubectl apply| Cert[cert-manager.io Certificate]
    Cert -.->|watches| Reconciler

    subgraph Controller["cert-manager-ext-issuer-secret-manager"]
        Reconciler[IssuerReconciler]
        Resolver{lookupResolver<br/>by IssuerRef.Kind}
        AWSR[AWSSecretResolver]
        GCPR[GCPSecretResolver]
        TCR[TencentSecretResolver]
        Parser[Extract&#40;payload, PayloadKeys&#41;]
        Kube[(k8s API)]
        Status[Status conditions<br/>Ready / Drift]
        Ticker[Resyncer ticker]
    end

    Reconciler --> Resolver
    Resolver -->|AWS kind| AWSR
    Resolver -->|GCP kind| GCPR
    Resolver -->|Tencent kind| TCR
    AWSR -->|GetSecretValue| AWSSM[(AWS Secrets Manager)]
    GCPR -->|AccessSecretVersion| GCPSM[(GCP Secret Manager)]
    TCR -->|DescribeCertificate| TCM[(Tencent SSL)]
    AWSSM -->|JSON| Parser
    GCPSM -->|JSON| Parser
    TCM -->|JSON| Parser
    Parser -->|PEM bytes| Kube
    Kube --> Secret[kubernetes.io/tls Secret]
    Reconciler --> Status
    Ticker -.->|periodic drift| Reconciler
```

Reconcile flow:

1. `IssuerReconciler.Reconcile` receives a `cert-manager.io/Certificate`.
2. Reads annotation `cert-manager.io/secret-manager-secret-name` → cloud-side ref.
3. `lookupResolver(cert.Spec.IssuerRef.Kind)` selects the `SecretResolver`
   registered for that kind (`AWSSecretManagerIssuer`, `GCPSecretManagerClusterIssuer`, …).
4. Resolver hits the cloud SDK, returns the JSON payload.
5. `Extract` parses the payload with `Issuer.spec.payloadKeys`
   (defaults: `certificate` / `private_key` / `certificate_chain`).
6. Controller builds a `kubernetes.io/tls` Secret (`tls.crt`, `tls.key`,
   optional `ca.crt` for the chain), owner-ref'd to the Certificate, and
   writes it to the same namespace.
7. `Ready` condition is set on the Certificate with a reason
   (`Synced` / `MissingSecretRef` / `SourceMissing` / `InvalidSpec` / `InvalidPayload`).
8. `Resyncer` ticks every `--resync-interval` (default 24h) for late drift
   detection (body deferred; reconciler covers immediate misses).

## Components

| Component | Path | Role |
|---|---|---|
| `cmd/main.go` | `cmd/` | Flag parser → `app.Run`. Flags: `--metrics-bind-address`, `--health-probe-bind-address`, `--leader-elect`, `--resync-interval`, `--cert-manager-namespace`. |
| `internal/app` | `internal/app/app.go` | Wires controller-runtime manager, builds per-kind `SecretResolver` map, registers reconciler + `Resyncer` + healthz/readyz. |
| `IssuerReconciler` | `internal/controller/issuer.go` | Watches `Certificate`. Dispatches by `IssuerRef.Kind`, fetches, parses, writes Secret. |
| `Resyncer` | `internal/controller/resync.go` | Periodic ticker; runs `Hash` checks across Issuers for late drift. |
| `Extract` | `internal/controller/parse.go` | JSON → `provider.Certificate{Certificate, PrivateKey, Chain}` using configured `PayloadKeys`. |
| `annotations` | `internal/controller/annotation.go` | `cert-manager.io/secret-manager-secret-name`, `cert-manager.io/secret-manager-force-sync`. |
| `conditions` | `internal/controller/conditions.go` | `Ready` condition helpers (`SetReady`, `SetSynced`). |
| `provider` | `internal/provider/provider.go` | `Provider` interface (`Fetch(ctx, ref) → *Certificate`) and shared `Certificate` struct. |
| AWS client | `internal/aws/client.go` | Real `secretsmanager` client (current build returns a wiring-deferred error; fakes in `internal/aws/fake`). |
| GCP client | `internal/gcp/client.go` | Real `secretmanager` client (same status as AWS). |
| Tencent client | `internal/tencent/client.go` | Adapter; real SDK wiring tracked in follow-up. |
| CRDs | `api/v1alpha1/` | `AWSSecretManagerIssuer`, `AWSSecretManagerClusterIssuer`, `GCPSecretManagerIssuer`, `GCPSecretManagerClusterIssuer`, `TencentSecretManagerIssuer`, `TencentSecretManagerClusterIssuer`. |
| RBAC | `config/rbac/role.yaml` | `ClusterRole` `cert-manager-ext-issuer-secret-manager`. |

### CRD spec shape (per-issuer; AWS example)

```yaml
spec:
  region: us-east-1          # AWS/Tencent only; GCP uses spec.project
  project: my-gcp-project    # GCP only
  secretRef:                 # optional — credentials; omit for IRSA / ADC
    name: aws-creds
    namespace: cert-manager  # resolved to cert ns for Issuer, flag ns for ClusterIssuer
  payloadKeys:               # optional overrides
    certificate: certificate
    privateKey: private_key
    certificateChain: certificate_chain
status:
  conditions:
    - type: Ready
      status: "True"
      reason: Synced
      message: secret reconciled from cloud
```

### Conditions

| Reason | Meaning |
|---|---|
| `Synced` | Secret written successfully. |
| `MissingSecretRef` | `cert-manager.io/secret-manager-secret-name` annotation absent. |
| `InvalidSpec` | Issuer kind unknown or `secretRef` Secret missing. |
| `SourceMissing` | Cloud SDK call failed (auth, network, not-found). |
| `InvalidPayload` | JSON parse or required field missing. |
| `Drift` | Resyncer detected source ≠ k8s Secret (future). |

Annotations:

- `cert-manager.io/secret-manager-secret-name` — **required**. Cloud-side identifier (AWS SM name, GCP resource name, Tencent cert ID).
- `cert-manager.io/secret-manager-force-sync` — set to force a re-fetch on next reconcile; cleared after success.

## Install

### Prerequisites

- Kubernetes 1.24+
- [cert-manager](https://cert-manager.io/docs/installation/) 1.14+
- Cloud credentials reachable from the controller pod:
  - **AWS**: IRSA (recommended) or `secretRef` with `access_key` / `secret_access_key` JSON.
  - **GCP**: Workload Identity (recommended) or `secretRef` with service-account JSON.
  - **Tencent**: CAM role via projected token or `secretRef` with `SecretId` / `SecretKey`.

### Build & deploy

```bash
# 1. Build the controller image
docker build -t ghcr.io/arindraaribudi/cert-manager-ext-issuer-secret-manager:latest .

# 2. Generate CRDs (requires controller-gen: go install sigs.k8s.io/controller-tools/cmd/controller-gen@latest)
make codegen

# 3. Install CRDs
kubectl apply -f config/crd/bases/

# 4. Install RBAC + deployment
kubectl apply -f config/rbac/role.yaml
# (see Sample deployment manifest below for the Deployment + ServiceAccount + ClusterRoleBinding)
```

The provided `config/rbac/role.yaml` defines the `ClusterRole`. A complete
deployment manifest is included in the Sample section.

### Flags

| Flag | Default | Notes |
|---|---|---|
| `--metrics-bind-address` | `:8080` | Prometheus metrics. |
| `--health-probe-bind-address` | `:8081` | `/healthz`, `/readyz`. |
| `--leader-elect` | `false` | Enable for HA (only one replica reconciles). |
| `--resync-interval` | `24h` | Drift-check cadence. `0` disables. |
| `--cert-manager-namespace` | `cert-manager` | Namespace to read `secretRef` for `ClusterIssuer` kinds when `secretRef.namespace` is empty. |

## Sample manifests

### 1. AWS (Issuer, namespaced)

```yaml
apiVersion: secret-manager.cert-manager.io/v1alpha1
kind: AWSSecretManagerIssuer
metadata:
  name: aws-prod
  namespace: app
spec:
  region: us-east-1
  # secretRef omitted → controller uses IRSA / pod identity
---
apiVersion: v1
kind: Secret
metadata:
  name: aws-credentials
  namespace: cert-manager
type: Opaque
stringData:
  access_key_id: AKIA...
  secret_access_key: ...
---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: app-tls
  namespace: app
  annotations:
    cert-manager.io/secret-manager-secret-name: prod/app-tls
spec:
  secretName: app-tls-secret
  duration: 2160h
  renewBefore: 720h
  issuerRef:
    name: aws-prod
    group: secret-manager.cert-manager.io
    kind: AWSSecretManagerIssuer
```

The AWS Secrets Manager entry `prod/app-tls` should be plain-text JSON:

```json
{
  "certificate": "-----BEGIN CERTIFICATE-----\nMII...\n-----END CERTIFICATE-----",
  "private_key": "-----BEGIN PRIVATE KEY-----\nMII...\n-----END PRIVATE KEY-----",
  "certificate_chain": "-----BEGIN CERTIFICATE-----\nMII...\n-----END CERTIFICATE-----"
}
```

### 2. AWS (ClusterIssuer)

```yaml
apiVersion: secret-manager.cert-manager.io/v1alpha1
kind: AWSSecretManagerClusterIssuer
metadata:
  name: aws-global
spec:
  region: eu-west-1
  secretRef:
    name: aws-creds
    namespace: cert-manager        # or empty → falls back to --cert-manager-namespace
  payloadKeys:
    certificate: cert
    privateKey: key
    certificateChain: chain
---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: api-tls
  namespace: backend
  annotations:
    cert-manager.io/secret-manager-secret-name: tls/api-prod
spec:
  secretName: api-tls-secret
  issuerRef:
    name: aws-global
    group: secret-manager.cert-manager.io
    kind: AWSSecretManagerClusterIssuer
```

### 3. GCP

```yaml
apiVersion: secret-manager.cert-manager.io/v1alpha1
kind: GCPSecretManagerClusterIssuer
metadata:
  name: gcp-prod
spec:
  project: my-gcp-project
  # Workload Identity recommended; or:
  secretRef:
    name: gcp-sa-key
    namespace: cert-manager
---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: web-tls
  namespace: frontend
  annotations:
    cert-manager.io/secret-manager-secret-name: projects/my-gcp-project/secrets/web-cert/versions/latest
spec:
  secretName: web-tls-secret
  issuerRef:
    name: gcp-prod
    group: secret-manager.cert-manager.io
    kind: GCPSecretManagerClusterIssuer
```

### 4. Tencent

```yaml
apiVersion: secret-manager.cert-manager.io/v1alpha1
kind: TencentSecretManagerIssuer
metadata:
  name: tencent-prod
  namespace: app
spec:
  region: ap-shanghai
  secretRef:
    name: tencent-creds
---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: tencent-tls
  namespace: app
  annotations:
    cert-manager.io/secret-manager-secret-name: ssl-cert-abc123
spec:
  secretName: tencent-tls-secret
  issuerRef:
    name: tencent-prod
    group: secret-manager.cert-manager.io
    kind: TencentSecretManagerIssuer
```

> **Status**: as of the current build, AWS and GCP resolvers return
> `wiring deferred — see plan §10 self-review`. The reconciler, parser,
> condition logic, CRDs, RBAC, and Issuer surface are all in place and
> covered by unit + demo tests; the SDK adapter wiring is tracked in the
> follow-up plan. Tencent uses the same plumbing with the placeholder
> error path.

### 5. Force sync

Trigger a one-shot re-fetch from the cloud by annotating the Certificate:

```bash
kubectl annotate certificate app-tls -n app cert-manager.io/secret-manager-force-sync=1
```

The controller clears the annotation on success.

## Deployment manifest

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: cert-manager-ext-issuer
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: cert-manager-ext-issuer-secret-manager
  namespace: cert-manager-ext-issuer
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: cert-manager-ext-issuer-secret-manager
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cert-manager-ext-issuer-secret-manager
subjects:
  - kind: ServiceAccount
    name: cert-manager-ext-issuer-secret-manager
    namespace: cert-manager-ext-issuer
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: cert-manager-ext-issuer-secret-manager
  namespace: cert-manager-ext-issuer
spec:
  replicas: 1
  selector:
    matchLabels:
      app: cert-manager-ext-issuer-secret-manager
  template:
    metadata:
      labels:
        app: cert-manager-ext-issuer-secret-manager
    spec:
      serviceAccountName: cert-manager-ext-issuer-secret-manager
      containers:
        - name: manager
          image: ghcr.io/arindraaribudi/cert-manager-ext-issuer-secret-manager:latest
          args:
            - --leader-elect
            - --cert-manager-namespace=cert-manager
          ports:
            - containerPort: 8080
              name: metrics
            - containerPort: 8081
              name: health
          readinessProbe:
            httpGet: { path: /readyz, port: health }
          livenessProbe:
            httpGet: { path: /healthz, port: health }
```

For AWS IRSA, annotate the ServiceAccount:

```yaml
metadata:
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::123456789012:role/cert-manager-ext-issuer
```

For GCP Workload Identity, add:

```yaml
metadata:
  annotations:
    iam.gke.io/gcp-service-account: cert-manager-ext-issuer@my-gcp-project.iam.gserviceaccount.com
```

## Build & test

```bash
make codegen    # regenerate CRDs + deep-copy
make build      # ./bin/manager
make test       # unit tests; envtest integration tests run when KUBEBUILDER_ASSETS is set
```