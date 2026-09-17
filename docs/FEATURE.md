# Feature: Mirror TLS Material from Cloud Secret Stores into Kubernetes Secrets

## Summary

- Mirrors TLS material from cloud secret stores into `kubernetes.io/tls` Secrets.
- Plugs into cert-manager as an **external issuer** — six CRDs in `secret-manager.cert-manager.io/v1alpha1` (AWS / GCP / Tencent × Issuer / ClusterIssuer).
- Fetch path: annotation → `IssuerRef.Kind` dispatch → cloud SDK → JSON parse → Secret write + CertificateRequest sign.
- Provider choice encoded in `IssuerRef.Kind`; reconciler stays provider-agnostic.
- Watch filter drops cert-manager built-in events; only `secret-manager.cert-manager.io` group reconciles.
- Annotation protocol: `cert-manager.io/secret-manager-secret-name` (required) + `cert-manager.io/secret-manager-force-sync` (optional).
- Cloud payload: JSON with `certificate` / `private_key` / `certificate_chain` (keys overridable per Issuer).
- Per-Issuer `payloadKeys`, per-ClusterIssuer `namespaceFilter` (Allow > Deny).
- GCP path works end-to-end (Workload Identity or ADC JSON via `secretRef`).
- AWS/Tencent resolvers stubbed — tracked as follow-ups.
- Periodic `Resyncer` ticker for late drift (default 24h, configurable via `--resync-interval`).
- Cert-manager compatibility: stamps `issuer-name` / `issuer-kind` / `issuer-group` annotations on issued Secrets to avoid `IncorrectIssuer`.

## Overview

`cert-manager-ext-issuer-secret-manager` is a Kubernetes controller that
plugs into [cert-manager](https://cert-manager.io) as an **external issuer**.
It watches `cert-manager.io/v1` `Certificate` resources whose `issuerRef`
points at one of six custom CRDs in the `secret-manager.cert-manager.io/v1alpha1`
group, fetches the corresponding TLS material from a cloud secret store, and
mirrors the result into a `kubernetes.io/tls` `Secret` in the same namespace(s).

The goal: let a cluster consume certificates that already live in AWS Secrets
Manager, GCP Secret Manager, or Tencent SSL — without re-issuing them — and
present them to cert-manager as if this controller had minted them locally.

The reconciler is provider-agnostic; provider choice is encoded in the
`IssuerRef.Kind`. New providers slot in by adding a CRD kind and registering
a `SecretResolver` closure in `internal/app/app.go`.

## Supported providers

| Provider | CRD kinds (namespaced + cluster) | Status |
|---|---|---|
| AWS Secrets Manager | `AWSSecretManagerIssuer`, `AWSSecretManagerClusterIssuer` | Real SDK + per-Issuer credential chain (IRSA or `secretRef`); `payloadKeys` JSON parse |
| GCP Secret Manager | `GCPSecretManagerIssuer`, `GCPSecretManagerClusterIssuer` | Real `cloud.google.com/go/secretmanager` client; per-project client cached via `sync.Once`; `secretRef`-based ADC JSON supported |
| Tencent SSL | `TencentSecretManagerIssuer`, `TencentSecretManagerClusterIssuer` | Real SDK + TKE OIDC / CVM / env credential chain; `payloadKeys` JSON parse |

All six kinds share a single `Spec` shape — `{ region | project, secretRef,
payloadKeys, namespaceFilter }` — so the reconciler treats them uniformly.

## CRD catalog

Group: `secret-manager.cert-manager.io`
Version: `v1alpha1`
Scope per kind: `Namespaced` for `*Issuer`, `Cluster` for `*ClusterIssuer`
Short names: `awssmi`, `awssmci`, `gcpsmi`, `gcpsmci`, `tencentsmi`, `tencentsmci`

### Spec

| Field | Applies to | Purpose |
|---|---|---|
| `region` | AWS, Tencent | Cloud region for the SDK client |
| `project` | GCP | GCP project ID owning the secrets |
| `secretRef` | all | Optional pointer to a k8s `Secret` holding credentials. Empty `namespace` is resolved to the Certificate's ns (Issuer) or `--cert-manager-namespace` flag (ClusterIssuer). Omit entirely to use pod identity (IRSA / Workload Identity / CAM) |
| `payloadKeys` | all | Override the JSON keys read from the cloud payload. Defaults: `certificate` / `private_key` / `certificate_chain` |
| `namespaceFilter` | ClusterIssuer only | `allow` list (whitelist) or `deny` list (blacklist) of namespaces for fan-out. Allow wins when both are set; neither set = every non-terminating namespace |

### Status

`status.conditions[]` is a `[]metav1.Condition`. The controller does not
currently write issuer-level status; the per-`Certificate` status (set by
the reconciler) is the user-facing signal.

## Annotation protocol

The controller extends the `Certificate` API with two annotations, both
under the `cert-manager.io/` prefix:

| Annotation | Required | Effect |
|---|---|---|
| `cert-manager.io/secret-manager-secret-name` | **yes** | Cloud-side identifier (AWS SM name/ARN, GCP `projects/p/secrets/s/versions/...`, Tencent cert ID). Missing → `Ready=False/MissingSecretRef` |
| `cert-manager.io/secret-manager-force-sync` | no | Set to force a re-fetch on next reconcile; cleared by the controller after a successful sync |

The reconciler also stamps the issued Secret with `cert-manager.io/issuer-name`,
`cert-manager.io/issuer-kind`, and `cert-manager.io/issuer-group` so
cert-manager's own controller trusts it as if it had been minted locally.
A missing `issuer-group` annotation defaults to `cert-manager.io` (matches
cert-manager's built-in behavior).

When the leaf cert parses, the controller also stamps informational
annotations on the Secret: `common-name`, `alt-names`, `not-before`,
`not-after`.

## Reconcile flow

1. **Watch filter.** Controller only reconciles `Certificate`s whose
   `spec.issuerRef.group == "secret-manager.cert-manager.io"` (`internal/app/app.go::ourIssuerFilter`).
   Events for cert-manager's built-in issuers are dropped at the predicate.
2. **Get Certificate.** `IssuerReconciler.Reconcile` (`internal/controller/issuer.go`).
3. **Annotation check.** Reads `cert-manager.io/secret-manager-secret-name`
   → `ref`. Missing → `Ready=False/MissingSecretRef`.
4. **Dispatch by Kind.** `lookupResolver(cert.Spec.IssuerRef.Kind)` looks up
   the registered `SecretResolver` in `ProviderResolvers`. Unknown kind →
   `Ready=False/InvalidSpec`.
5. **Fetch bytes.** Resolver calls the cloud SDK and returns the raw JSON
   payload. SDK error → `Ready=False/SourceMissing` with the SDK error message.
6. **Load Issuer config.** `IssuerConfigFromIssuer` reads the matching Issuer
   (`loadIssuerConfig` in `app.go`) → `IssuerConfig{PayloadKeys, NamespaceFilter}`.
7. **Parse payload.** `controller.Extract(payload, cfg.PayloadKeys)`
   (`internal/controller/parse.go`) decodes JSON with the configured keys,
   unescapes the string fields into PEM bytes, returns
   `provider.Certificate{Certificate, PrivateKey, Chain}`. Missing required
   field → `Ready=False/InvalidPayload`.
8. **Compute target namespaces.** Namespaced Issuer → just the Certificate's
   ns. ClusterIssuer-kind → fan-out per `NamespaceFilter` (Allow > Deny,
   skip terminating namespaces).
9. **Write Secret.** For each target ns, `writeSecret` tries `Update`,
   falls back to `Create` on NotFound. Secret is `kubernetes.io/tls`
   (`tls.crt`, `tls.key`, optional `ca.crt` for the chain), owner-ref'd
   to the Certificate *only* in the Certificate's own namespace (cross-ns
   owner refs are silently dropped by kube-apiserver GC).
10. **Sign matching CertificateRequest.** `signCertificateRequest` looks up
    `<cert-name>-1`, stamps `Ready=True` with the fetched cert bytes and CA.
    Best-effort: if the CR doesn't exist yet, the issuing controller will
    create one and we'll sign it on the next reconcile.
11. **Clear force-sync.** If the annotation was set, it's removed and the
    Certificate is `Update`'d.
12. **Set Ready=True/Synced.**

## Conditions (Certificate status)

| Reason | Meaning |
|---|---|
| `Synced` | Secret written and CR signed |
| `MissingSecretRef` | Annotation `cert-manager.io/secret-manager-secret-name` absent |
| `InvalidSpec` | Unknown `IssuerRef.Kind` or referenced Issuer not found |
| `SourceMissing` | Cloud SDK call failed (auth, network, not-found) |
| `InvalidPayload` | JSON parse failed or required PEM field missing |
| `SignCRFailed` | CR status update failed (rare; usually RBAC) |

`Ready=True` with reason `Synced` is the only "happy path" condition.

## Cloud-side payload format

Each cloud secret stores a JSON object whose three string fields hold PEM
material. Default key names:

```json
{
  "certificate":       "-----BEGIN CERTIFICATE-----\nMII...\n-----END CERTIFICATE-----",
  "private_key":       "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----",
  "certificate_chain": "-----BEGIN CERTIFICATE-----\nMII...\n-----END CERTIFICATE-----"
}
```

The chain field is optional. Key names are overridable per Issuer via
`spec.payloadKeys` (`certificate` / `privateKey` / `certificateChain` →
JSON tag). Values that JSON-encode to `""` are treated as missing.

The controller stores PEM bytes verbatim — no chain concatenation, no
cert validation. Validation belongs to the consumer.

## GCP-specific details

- Client is built once via `sync.Once` and reused across all reconcile
  calls (`gcpResolver` in `app.go`).
- `New(ctx, adcJSON)` uses `option.WithCredentialsJSON(adcJSON)` when
  the Issuer's `secretRef` provides one; otherwise the default ADC chain
  (Workload Identity, GKE metadata server, `GOOGLE_APPLICATION_CREDENTIALS`,
  gcloud user creds) applies.
- `Fetch(ctx, client, ref)` calls `AccessSecretVersion` with the full
  resource name.
- `normalizeGCPVersion` (`app.go`) appends `/versions/latest` when the ref
  has no `/versions/` segment; explicit-version refs (`/versions/<n>`)
  pass through for pin-to-version support.

Sample annotation value for a GCP-managed cert:
```
projects/my-project/secrets/web-tls/versions/latest
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│ cert-manager                                                    │
│  Certificate ──► issuing controller ──► CertificateRequest      │
└────────────────────────────┬────────────────────────────────────┘
                             │ watches
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│ cert-manager-ext-issuer-secret-manager                          │
│                                                                 │
│   ourIssuerFilter() ──► IssuerReconciler.Reconcile              │
│                          │                                      │
│                          ├─► lookupResolver(IssuerRef.Kind)     │
│                          │     ├─► AWS  Secrets Manager (TBD)    │
│                          │     ├─► GCP  Secret Manager          │
│                          │     └─► Tencent SSL       (stub)     │
│                          │                                      │
│                          ├─► loadIssuerConfig(Issuer)           │
│                          │                                      │
│                          ├─► Extract(payload, PayloadKeys)      │
│                          │                                      │
│                          ├─► targetNamespaces(Issuer, Filter)   │
│                          │                                      │
│                          ├─► writeSecret(corev1.Secret)         │
│                          │                                      │
│                          └─► signCertificateRequest(CR)          │
│                                                                 │
│   Resyncer ticker ──► Reconcile (every --resync-interval)       │
└─────────────────────────────────────────────────────────────────┘
```

Component ownership:

| Path | Role |
|---|---|
| `cmd/main.go` | Flag parser → `app.Run` |
| `internal/app/app.go` | Builds `ProviderResolvers` + `IssuerConfigFromIssuer`, registers reconciler + Resyncer + healthz/readyz |
| `internal/controller/issuer.go` | The reconcile loop |
| `internal/controller/parse.go` | JSON → `provider.Certificate` |
| `internal/controller/resync.go` | Periodic drift ticker |
| `internal/controller/conditions.go` | Ready/CR condition helpers |
| `internal/controller/annotation.go` | Annotation constants + getters |
| `internal/provider/provider.go` | Shared `Certificate` struct + `Provider` interface (declared; not yet the reconciler-facing shape) |
| `internal/{aws,gcp,tencent}/client.go` | Real cloud SDK clients |
| `internal/awscert/`, `internal/tencentcert/` | Certificate download controllers (ACM + Tencent SSL) |
| `internal/controller/{awscert,tencentcert}/` | Reconcilers + RBAC for the cert download CRDs |
| `internal/{aws,gcp,tencent}/fake/` | In-memory fakes for tests + `demo-*` binaries |
| `api/v1alpha1/` | CRD types + `IssuerConfig` / `PayloadKeys` / `NamespaceFilter` / `SecretRef` shared shapes |
| `cmd/demo-{aws,gcp,tencent}/main.go` | Runnable end-to-end check against the fakes |
| `config/crd/bases/` | Generated CRD manifests |
| `config/rbac/role.yaml` | ClusterRole |
| `config/manager/` | Deployment + ServiceAccount + namespace + role-binding |

## Install

```bash
# Build image
docker build -t ghcr.io/arindraaribudi/cert-manager-ext-issuer-secret-manager:latest .

# Generate CRDs (requires controller-gen)
make codegen

# Install
kubectl apply -f config/crd/bases/
kubectl apply -f config/rbac/role.yaml
kubectl apply -f config/manager/
```

### Prerequisites

- Kubernetes 1.24+
- cert-manager 1.14+
- Cloud credentials reachable from the pod (IRSA / Workload Identity / CAM recommended, or `secretRef` to a k8s Secret holding credentials)

### Controller flags

| Flag | Default | Notes |
|---|---|---|
| `--metrics-bind-address` | `:8080` | Prometheus scrape |
| `--health-probe-bind-address` | `:8081` | `/healthz`, `/readyz` |
| `--leader-elect` | `false` | Enable for HA |
| `--resync-interval` | `24h` | Drift-check cadence; `0` disables |
| `--cert-manager-namespace` | `cert-manager` | Fallback ns for `ClusterIssuer` `secretRef.namespace` |

## Example: GCP end-to-end

```yaml
apiVersion: secret-manager.cert-manager.io/v1alpha1
kind: GCPSecretManagerClusterIssuer
metadata:
  name: gcp-prod
spec:
  project: my-gcp-project
  # Workload Identity on the controller's KSA — no secretRef needed
```

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: web-tls
  namespace: frontend
  annotations:
    cert-manager.io/secret-manager-secret-name: projects/my-gcp-project/secrets/web-tls/versions/latest
spec:
  secretName: web-tls-secret
  issuerRef:
    name: gcp-prod
    group: secret-manager.cert-manager.io
    kind: GCPSecretManagerClusterIssuer
```

Cloud-side secret payload in GCP Secret Manager:

```json
{
  "certificate":       "-----BEGIN CERTIFICATE-----\nMII...\n-----END CERTIFICATE-----",
  "private_key":       "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----",
  "certificate_chain": "-----BEGIN CERTIFICATE-----\nMII...\n-----END CERTIFICATE-----"
}
```

After reconcile:
- `kubernetes.io/tls` Secret `web-tls-secret` exists in `frontend`
  (and every other non-terminating namespace, unless filtered), with
  `tls.crt`, `tls.key`, `ca.crt`.
- The Certificate's `status.conditions[].type=Ready` is `True`,
  `reason=Synced`.
- The matching `CertificateRequest web-tls-1` has `status.conditions[].type=Ready=True`,
  `status.certificate` set.

## Force re-sync

```bash
kubectl annotate certificate web-tls -n frontend \
  cert-manager.io/secret-manager-force-sync=1
```

Controller re-fetches from the cloud on the next event and clears the
annotation after a successful sync. Useful after rotating a cert in the
cloud store.

## Known gaps & follow-ups

1. **Resyncer drift detection** — the ticker (`internal/controller/resync.go`)
   re-`Reconcile`s every matching Certificate. The original plan called
   for `Hash(payload)` comparison to avoid redundant writes; today every
   tick rewrites the Secret. Cheap when secrets are stable; wasteful when
   they churn.
2. **Issuer-level status** — CRDs declare `Status.Conditions` but the
   controller doesn't write to them. Users watch the Certificate's
   `Ready` condition instead.

## Certificate download controllers (ACM / Tencent SSL)

A second CRD group — `certificates.cert-manager.io/v1alpha1` — mirrors
**already-issued** cloud certificates into a `kubernetes.io/tls` Secret.
Out-of-band issuance: you control the cert lifecycle in the cloud CA,
the controller only downloads and mirrors.

| Kind | Scope | Provider |
|---|---|---|
| `AWSCertificateClusterIssuer` | Cluster | AWS Certificate Manager (`DescribeCertificate` + `ExportCertificate`, PKCS#8-encrypted private key) |
| `TencentCertificateClusterIssuer` | Cluster | Tencent SSL (`DownloadCertificate` ZIP → leaf/chain/key extract) |

Cluster scope is required by `kubebuilder` for these kinds. The default
`--resync-interval` is `12h` for cert controllers (vs `24h` for secret
managers).

Annotations the controllers read on the `Certificate`:

| Annotation | Provider |
|---|---|
| `acm.cert-manager.io/certificate-arn` | ACM ARN |
| `tencent.cert-manager.io/certificate-id` | Tencent cert ID |

Private-key export from ACM requires a `passphrase` key in the same k8s
`Secret` referenced by `spec.secretRef`. Public ACM certs skip decrypt
automatically. ACM public certs issued before 2025-06-17 cannot be
exported — surfaces as `DescribeFailed`.

## Tests

- `internal/controller/{issuer,parse,conditions,annotation,resync}_test.go`
  — unit tests for the secret-manager reconciler, parser, and helpers.
  Use the fake clients where a real SDK call would otherwise be needed.
- `internal/awscert/{client,credentials}_test.go`,
  `internal/tencentcert/{ssl,credentials}_test.go` — unit tests for the
  ACM / Tencent SSL fetch + credential-chain layers.
- `internal/controller/{awscert,tencentcert}/issuer_test.go` — reconcile
  loops for the cert download controllers; run under envtest when
  `KUBEBUILDER_ASSETS` is set.
- `internal/{aws,gcp,tencent}/fake/client_test.go` — fake round-trip.
- `controller/setup_envtest_test.go` — envtest harness.
- `cmd/demo-{aws,gcp,tencent}/main.go` — single-shot runnable end-to-end
  checks against the fakes. Useful as smoke tests for the
  fetch → parse → build-Secret pipeline.

Build/test/lint:

```bash
make codegen    # regenerate CRDs + deep-copy
make build      # ./bin/manager
make test       # unit tests
make lint       # golangci-lint v2.13.2+
make audit      # govulncheck
make scan       # trivy on the built image
```

## Toolchain

- Go **1.27** (Dockerfile base `golang:1.27`)
- `golangci-lint` **v2.13.2** or newer (must be built with Go ≥ 1.27 to
  decode the current export format)
- `controller-gen` (CRD + deep-copy generation)
- `trivy` (HIGH/CRITICAL image scan), `govulncheck` (Go vuln scan)
