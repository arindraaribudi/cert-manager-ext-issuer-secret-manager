// Package casource — shared reconcile skeleton for the three cloud
// Secret Manager CA-source CRDs. Each per-cloud file (aws.go, gcp.go,
// tencent.go) provides a Fetch closure and a typed Reconcile method
// that pulls spec fields and delegates here.
//
// ponytail: a per-cloud Reconciler with the typed CRD in scope is the
// smallest change in the right place. The shared skeleton avoids
// duplicating the parse + write + status dance three times.
package casource

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	api "github.com/arindraaribudi/cert-manager-ext-issuer-secret-manager/api/v1alpha1"
	"github.com/arindraaribudi/cert-manager-ext-issuer-secret-manager/internal/controller"
)

const (
	defaultResyncInterval = 24 * time.Hour
	defaultTargetNS       = "cert-manager"
	conditionReady        = "Ready"
	chainField            = "certificate_chain"
)

// FetchSpec is the resolved per-CRUD spec the Fetch closure consumes.
// Built by each per-cloud Reconcile from its typed CASource + wire-up
// config (CMNamespace for SecretRef ns fallback).
type FetchSpec struct {
	Region      string
	Endpoint    string
	Project     string // GCP only
	SecretName  string
	SecretRef   *api.SecretRef
	CMNamespace string
}

// FetchFunc pulls a CA JSON payload from the cloud Secret Manager.
// Implementations cache SDK clients where it makes sense (AWS, Tencent
// by region|endpoint; GCP per-call).
type FetchFunc func(ctx context.Context, spec FetchSpec) ([]byte, error)

// Reconciler is the shared CASource reconcile skeleton. Per-cloud files
// embed it and provide a typed Reconcile method that wraps the typed
// CRD into ReconcileInput and persists the returned ReconcileStatus.
type Reconciler struct {
	client.Client
	Prefix string
	Fetch  FetchFunc
}

// ReconcileInput is the per-CRUD spec the shared skeleton needs.
// Each per-cloud Reconcile builds one and passes it to .Reconcile.
type ReconcileInput struct {
	Region         string
	Endpoint       string
	Project        string
	SecretName     string
	SecretRef      *api.SecretRef
	TargetNS       string
	TargetName     string
	ResyncInterval time.Duration
}

// ReconcileStatus is what the shared reconcile returns for the caller
// to persist on the typed CRD's status subresource.
type ReconcileStatus struct {
	Conditions   []metav1.Condition
	SourceHash   string
	LastSyncTime string
}

// Reconcile does the fetch → parse → write Opaque → status dance.
// On error it returns the reason string for the caller to flip
// Ready=False; on success it returns a fully populated status.
func (r *Reconciler) Reconcile(ctx context.Context, in ReconcileInput, prevConditions []metav1.Condition) (ctrl.Result, *ReconcileStatus, error) {
	if in.TargetNS == "" {
		in.TargetNS = defaultTargetNS
	}
	if in.ResyncInterval == 0 {
		in.ResyncInterval = defaultResyncInterval
	}

	fetchSpec := FetchSpec{
		Region:      in.Region,
		Endpoint:    in.Endpoint,
		Project:     in.Project,
		SecretName:  in.SecretName,
		SecretRef:   in.SecretRef,
		CMNamespace: in.TargetNS, // fall-back ns for empty SecretRef.Namespace lives with the rest of the spec
	}
	payload, err := r.Fetch(ctx, fetchSpec)
	if err != nil {
		return ctrl.Result{}, nil, fmt.Errorf("fetch %q: %w", in.SecretName, err)
	}
	ca, err := extractChain(payload)
	if err != nil {
		return ctrl.Result{}, nil, fmt.Errorf("parse: %w", err)
	}
	h := sourceHash(ca)
	now := time.Now().UTC().Format(time.RFC3339)
	secret := buildOpaque(in.TargetNS, in.TargetName, ca, h, now)
	if err := r.writeSecret(ctx, secret); err != nil {
		return ctrl.Result{}, nil, fmt.Errorf("write secret: %w", err)
	}

	conds := appendOrReplace(prevConditions, metav1.Condition{
		Type:    conditionReady,
		Status:  metav1.ConditionTrue,
		Reason:  "Synced",
		Message: fmt.Sprintf("CA synced from %s secret %q", r.Prefix, in.SecretName),
	})
	return ctrl.Result{RequeueAfter: in.ResyncInterval}, &ReconcileStatus{
		Conditions:   conds,
		SourceHash:   h,
		LastSyncTime: now,
	}, nil
}

// extractChain parses `{"certificate_chain": "PEM..."}` from a cloud SM
// payload. Only the chain field is read — CASource never needs a leaf
// or private key (trust-manager consumes CA bundles as a single PEM).
func extractChain(payload []byte) ([]byte, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(payload, &raw); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}
	chainRaw, ok := raw[chainField]
	if !ok || len(chainRaw) == 0 || string(chainRaw) == `""` {
		return nil, fmt.Errorf("missing field %q", chainField)
	}
	var s string
	if err := json.Unmarshal(chainRaw, &s); err != nil {
		return nil, fmt.Errorf("%s not a string: %w", chainField, err)
	}
	return []byte(s), nil
}

func sourceHash(ca []byte) string {
	sum := sha256.Sum256(ca)
	return hex.EncodeToString(sum[:])
}

func buildOpaque(ns, name string, ca []byte, hash, lastSync string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns,
			Name:      name,
			Annotations: map[string]string{
				controller.AnnotationSourceHash:   hash,
				controller.AnnotationLastSyncTime: lastSync,
			},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			"ca.crt": ca,
		},
	}
}

// writeSecret creates or updates the target Opaque Secret. Annotations
// + Data are replaced wholesale on update; cluster-admin-owned
// out-of-band edits to data["ca.crt"] are intentionally overwritten on
// the next reconcile (the controller is the source of truth for the
// material it fetches).
func (r *Reconciler) writeSecret(ctx context.Context, desired *corev1.Secret) error {
	existing := &corev1.Secret{}
	err := r.Get(ctx, types.NamespacedName{Namespace: desired.Namespace, Name: desired.Name}, existing)
	if apierrors.IsNotFound(err) {
		return r.Create(ctx, desired)
	}
	if err != nil {
		return err
	}
	existing.Data = desired.Data
	existing.Annotations = desired.Annotations
	return r.Update(ctx, existing)
}

func appendOrReplace(conds []metav1.Condition, c metav1.Condition) []metav1.Condition {
	for i, existing := range conds {
		if existing.Type == c.Type {
			conds[i] = c
			return conds
		}
	}
	return append(conds, c)
}
