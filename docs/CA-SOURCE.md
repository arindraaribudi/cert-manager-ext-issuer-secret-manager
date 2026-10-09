# CA-Source: trust-manager CAs from cloud Secret Managers

## Context

`cert-manager-ext-issuer-secret-manager` mirrors TLS material (leaf + key + chain) from AWS Secrets Manager / GCP Secret Manager / Tencent SSM into k8s `kubernetes.io/tls` Secrets. **CA distribution is the missing half** — the user wants trust-manager to consume CAs that live in cloud Secret Managers, using pod identity / workload identity federation.

**trust-manager's hard constraint:** `Bundle.spec.sources` (v1alpha1) and `ClusterBundle.spec.sourceRefs` (v1alpha2) are enum-limited to `ConfigMap` / `Secret` / `InLine` / `UseDefaultCAs`. There is **no plugin, no webhook receiver, no SPI**. The only way to feed external CAs is to materialize them into a k8s `Secret` and reference that Secret from the Bundle.

**Topology (confirmed):** same cluster, same namespace as cert-manager + trust-manager. The new controller writes the Secret in-namespace; trust-manager reads it from the same namespace. No cross-cluster or cross-namespace plumbing needed.

**Prerequisite: revert `e831dc8` first.** That commit introduced a half-broken chain-only path: the parser relaxation is fine, but the writer still emits `SecretTypeTLS` with an empty `tls.key`, which the k8s API server rejects at admission (see `revert.md` "Why revert"). The new CASource CRDs do not need the parser relaxation either — they ship their own 8-line JSON parser inside `internal/controller/casource/` and write `Opaque` Secrets directly. Revert first, then add the new code. After revert, the leaf+key flow goes back to requiring `certificate` + `private_key` (the correct behaviour for end-entity TLS).

**Outcome:** three new cluster-scoped CRDs (`AWSSecretManagerCASource`, `GCPSecretManagerCASource`, `TencentSecretManagerCASource`) that fetch the CA JSON from the cloud Secret Manager and write a k8s `Opaque` Secret with `ca.crt`. trust-manager `Bundle` (v1alpha1) or `ClusterBundle` (v1alpha2) references that Secret.

**Cloud identity:** zero controller code for AWS + GCP (SDK chain / ADC walks to pod identity). Tencent already wires `IsTkePodIdentity` + `DefaultTkeOIDCRoleArnProvider` in `internal/tencent/client.go:111`. ServiceAccount annotation is the only thing the user must set per cluster (IRSA `eks.amazonaws.com/role-arn`, GKE WI `iam.gke.io/gcp-service-account`, TKE OWI `eks.tke.cloud.tencent.com/role-arn`).

## Approach

Add a thin controller package `internal/controller/casource/` that wraps the existing AWS / GCP / Tencent fetchers around three new CRD types. No new SDK imports, no new parsers, no new drift machinery, no new identity plumbing.

### CRD shape (cluster-scoped, one per cloud)

File: `api/v1alpha1/casource_types.go` (new, ~120 lines, 3 kinds + 3 lists).

```go
type AWSSecretManagerCASourceSpec struct {
    SecretRef       *SecretRef       `json:"secretRef,omitempty"`        // nil → IRSA / Pod Identity
    Region          string           `json:"region"`                     // required
    Endpoint        string           `json:"endpoint,omitempty"`         // optional, VPC / LocalStack
    SecretName      string           `json:"secretName"`                 // required
    Target          CASourceTarget   `json:"target"`                     // required
    ResyncInterval  metav1.Duration  `json:"resyncInterval,omitempty"`  // default 24h
}

type CASourceTarget struct {
    Namespace string `json:"namespace,omitempty"` // default "cert-manager"
    Name      string `json:"name"`                // required, becomes Secret/<ns>/<name>
}

type CASourceStatus struct {
    Conditions   []metav1.Condition `json:"conditions,omitempty"`
    SourceHash   string             `json:"sourceHash,omitempty"`
    LastSyncTime string             `json:"lastSyncTime,omitempty"`
}
```

`GCPSecretManagerCASourceSpec` swaps `Region` for `Project string`. `TencentSecretManagerCASourceSpec` keeps `Region string` and adds optional `SecretRef` (AK/SK fallback when not on TKE).

**Validation markers only** (no webhook, consistent with existing 6 Issuer CRDs in `api/v1alpha1/awsissuer_types.go`):
- `+kubebuilder:validation:Required` on `Region`/`Project`, `SecretName`, `Target.Name`.
- `+kubebuilder:validation:Pattern=^[a-z0-9]([-a-z0-9]*[a-z0-9])?$` on `Target.Name`.

Register in `api/v1alpha1/groupversion_info.go:33-42` (append 3 kinds + 3 lists to `SchemeBuilder.Register(...)`).

### Reconciler — three cloud adapters, one shared engine

New package `internal/controller/casource/`:

- `casource.go` (~120 lines): generic `Reconciler{client.Client, Scheme, Fetch, Resolve, Prefix}`. `Reconcile` calls `Resolve` → `Fetch` → `extractChain(payload)` (8-line in-package JSON parse, returns `{"certificate_chain": "PEM"}` field) → builds an `Opaque` k8s `Secret` with only `data["ca.crt"]` = full PEM bundle → stamps `cert-manager.io/secret-manager-source-hash` + `last-sync-time` annotations on the Secret → updates status conditions → `ctrl.Result{RequeueAfter: r.ResyncInterval}`. **Does not call `controller.WriteSecret`** — that path emits `SecretTypeTLS` and is the wrong shape for a CA bundle.
- `aws.go` (~50 lines): `Fetch` closure calls existing `aws.New(ctx, region, endpoint).Fetch(ctx, name)`. Cached by `region|endpoint`, mirrors `internal/app/app.go:181-213`.
- `gcp.go` (~50 lines): `Fetch` closure calls existing `gcp.New(...).Fetch(...)`. ADC chain handles WI. Mirrors `internal/app/app.go:296-316`.
- `tencent.go` (~50 lines): `Fetch` closure calls existing `tencent.New(...).Fetch(...)`. Reuses `tencent.ResolveCredential` (`internal/tencent/client.go:159-172`) which already handles `IsTkePodIdentity` + static AK/SK fallback. Mirrors `internal/app/app.go:346-379`.

**Wiring** in `internal/app/app.go:140-156`: append 3 `mgr.GetClient()` SetupWithManager calls after the existing `awscertctrl` / `tencentcertctrl` setup. Each adapter registers `For(&AWSSecretManagerCASource{}, ...).Complete(r)` (controller-runtime, no extra predicate — these CRDs are rare).

### Identity wiring (per cloud, no controller code changes)

- **AWS**: SA annotation `eks.amazonaws.com/role-arn: arn:aws:iam::ACCT:role/<name>`. SDK chain reads `AWS_ROLE_ARN` + `AWS_WEB_IDENTITY_TOKEN_FILE` (IRSA) or `AWS_CONTAINER_CREDENTIALS_FULL_URI` (EKS Pod Identity). `config/manager/serviceaccount.yaml` already in repo — no change.
- **GCP**: SA annotation `iam.gke.io/gcp-service-account: <gcp-sa>@<project>.iam.gserviceaccount.com`. ADC walks to GKE metadata server. No env, no volume.
- **Tencent**: SA annotation `eks.tke.cloud.tencent.com/role-arn: qcs::cam::uin/<uin>:roleName/<role>`. SDK `common.DefaultTkeOIDCRoleArnProvider()` reads `TKE_REGION` + `TKE_WEB_IDENTITY_TOKEN_FILE` injected by TKE. `internal/tencent/client.go:111` already detects + wires this.

If `Spec.SecretRef` set → static creds (existing k8s Secret pattern, `internal/awscert/credentials.go:29` / `internal/gcp/client.go:18-31` / `internal/tencent/client.go:160`). Otherwise ambient pod identity wins.

### trust-manager handoff

**`config/samples/awssm-bundle.yaml` (v1alpha1 Bundle, namespaced):**

```yaml
apiVersion: trust.cert-manager.io/v1alpha1
kind: Bundle
metadata:
  name: aws-roots
spec:
  sources:
    - secret: {name: aws-roots, key: ca.crt}
  target:
    secret: {key: ca.crt}
```

**`config/samples/awssm-clusterbundle.yaml` (v1alpha2 ClusterBundle, cluster-wide):**

```yaml
apiVersion: trust.cert-manager.io/v1alpha2
kind: ClusterBundle
metadata:
  name: aws-roots
spec:
  sourceRefs:
    - kind: Secret
      name: aws-roots
```

**`config/samples/awssm-casource.yaml`** (analog for `gcpsm-casource.yaml` / `tencentsm-casource.yaml`):

```yaml
apiVersion: secret-manager.cert-manager.io/v1alpha1
kind: AWSSecretManagerCASource
metadata: {name: aws-roots}
spec:
  region: us-east-1
  secretName: my-ca-bundle
  target:
    namespace: cert-manager
    name: aws-roots
```

Cloud SM entry shape (matches existing convention used by leaf/key issuers):
```json
{"certificate_chain": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n"}
```

### RBAC

Append to `config/rbac/role.yaml:20-37`:
```yaml
- "awssecretmanagercasources"
- "awssecretmanagercasources/status"
- "gcpsecretmanagercasources"
- "gcpsecretmanagercasources/status"
- "tencentsecretmanagercasources"
- "tencentsecretmanagercasources/status"
```

No new verbs (existing `get, list, watch, update, patch` + `secrets` write covers the target Secret). No `signers` entries — these CRDs don't sign `CertificateRequest`s.

## Files

**Add (6 source + 6 sample files):**
- `api/v1alpha1/casource_types.go` — 3 types + 3 list types, ~120 lines
- `internal/controller/casource/casource.go` — shared reconciler, ~120 lines
- `internal/controller/casource/aws.go` — AWS adapter, ~50 lines
- `internal/controller/casource/gcp.go` — GCP adapter, ~50 lines
- `internal/controller/casource/tencent.go` — Tencent adapter, ~50 lines
- `config/samples/{aws,gcp,tencent}sm-casource.yaml`
- `config/samples/{aws,gcp,tencent}sm-bundle.yaml` + `{aws,gcp,tencent}sm-clusterbundle.yaml` (6 trust-manager samples total)

**Modify (5 files):**
- `api/v1alpha1/groupversion_info.go:33-42` — register 6 types
- `internal/app/app.go:140-156` — append 3 SetupWithManager calls
- `config/rbac/role.yaml:20-37` — append 6 resource names
- `docs/FEATURE.md` — new section
- `docs/COMPONENTS.md` — 3 component cells

**Regenerated (no hand edit):**
- `api/v1alpha1/zz_generated.deepcopy.go` — `make generate`
- `config/crd/bases/*.yaml` — `make manifests`
- `config/install.yaml` — `make bundle`

**Reused, no change:**
- `internal/controller/annotation.go`, `hash.go`, `conditions.go` — drift machinery (annotation constants for source-hash / last-sync-time)
- `internal/aws/*` — client + IRSA chain
- `internal/gcp/*` — client + ADC chain
- `internal/tencent/*` — client + TKE OWI chain
- `config/manager/serviceaccount.yaml` — controller SA
- `go.mod` — no new dependencies

**Explicitly NOT reused:**
- `internal/controller/parse.go:Extract` — after revert this requires `certificate` + `private_key`. New CASource has its own JSON parser.
- `internal/controller/issuer.go:WriteSecret` — emits `SecretTypeTLS`. New CASource writes `Opaque` Secret directly.
- `internal/keystore/keystore.go:BuildTruststore` — reverts with `e831dc8`. New CASource doesn't need JKS — trust-manager consumes PEM.

## Verification

**Unit (load-bearing):**
- `internal/controller/casource/casource_test.go` (new) — fake `Reconciler` with in-memory `Fetch` closure feeding `{"certificate_chain": "..."}`. Assert target `Secret.Data["ca.crt"]` equals the input PEM bytes, `Secret.Type` == `Opaque`, no `tls.crt`/`tls.key` keys. Uses `client/fake` from controller-runtime.

**End-to-end demo:** extend `cmd/demo/main.go` with a `-casource` flag that wires the fake AWS/GCP/Tencent resolvers through the new `casource.Reconciler` and prints the resulting Secret's `ca.crt` length. Single runnable check, no new framework.

**Manual smoke:**
1. `git revert --no-edit e831dc8` — drop the half-broken chain-only commit.
2. `make manifests generate bundle` then `kubectl apply -f config/install.yaml` in the cluster.
3. `kubectl apply -f config/samples/awssm-casource.yaml` (with AWS creds via IRSA wired on the controller SA).
4. Wait for `kubectl get awssmca aws-roots -o jsonpath='{.status.conditions}'` to show `Ready=True`.
5. `kubectl get secret -n cert-manager aws-roots -o jsonpath='{.data.ca\.crt}' | base64 -d` → expect full PEM chain. Confirm `Secret.Type` is `Opaque`.
6. `kubectl apply -f config/samples/awssm-bundle.yaml` (v1alpha1) and/or `awssm-clusterbundle.yaml` (v1alpha2).
7. `kubectl get bundle aws-roots -o jsonpath='{.status.conditions}'` → `Ready=True` (trust-manager validates the Secret we wrote).
8. Repeat for GCP and Tencent.

## Skipped (and when to add)

- **Namespaced CASource variants** — trust-manager is cluster-scoped. Single scope per cloud. Add if a tenant boundary becomes a hard requirement.
- **Webhook validation** — runtime check in the reconciler covers the one required-field case. Add when the CRD surface passes ~10 fields.
- **Force-sync annotation** — not in scope for chain-only path. Add if rotation cadence needs manual kick.
- **Multiple CAs per CRD** — one Secret per CRD. Add if a tenant needs to fan-out a single cloud SM entry to N k8s Secrets.
- **TLS Secret type** — we write `Opaque`. If a downstream app needs the same Secret to be `kubernetes.io/tls`, write an empty `tls.key` and switch the type. Out of scope.
- **JKS / PKCS12 truststore output** — trust-manager only consumes PEM. Reverted code path is dead; not resurrected.
