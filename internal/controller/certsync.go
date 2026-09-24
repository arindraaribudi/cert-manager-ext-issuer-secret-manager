// Package controller — CertSyncer is the shared Reconcile driver for
// cert-mirroring controllers (awscertctrl, tencentcertctrl). Each cloud
// implements CertSource; CertSyncer owns everything else: annotation
// gating, finalizer handling, Secret assembly, keystore build, namespace
// fan-out, write, verify, and Ready/drift condition management.
package controller

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"

	api "github.com/arindraaribudi/cert-manager-ext-issuer-secret-manager/api/v1alpha1"
	"github.com/arindraaribudi/cert-manager-ext-issuer-secret-manager/internal/keystore"
)

// FinalizerName is added to every Certificate a cert-mirror reconciler
// manages, so we get a delete hook. Shared across awscertctrl and
// tencentcertctrl (previously a private const duplicated in both).
const FinalizerName = "certificates.cert-manager.io/finalizer"

// FetchResult is what a CertSource.Fetch returns on success: the parsed,
// normalized, chain-verified PEM material plus the per-cert config the
// driver needs downstream.
type FetchResult struct {
	LeafPEM, ChainPEM, KeyPEM []byte
	// ExtraAnnotations are stamped onto the Secret in addition to the
	// common issuer/hash/cert annotations the driver always sets. Most
	// providers leave this nil.
	ExtraAnnotations map[string]string
	NamespaceFilter  api.NamespaceFilter
	ResyncInterval   time.Duration
}

// CertSource is the provider-specific half of a cert-mirror reconciler.
type CertSource interface {
	// Prefix names the provider in log/error/condition messages, e.g.
	// "awscert", "tencentcert".
	Prefix() string
	// AnnotationKey is the Certificate annotation that both gates whether
	// this reconciler handles the cert and carries the source identifier
	// (ARN, cert ID, ...).
	AnnotationKey() string
	// Fetch resolves the issuer, loads credentials, builds/reuses an SDK
	// client, downloads and chain-verifies the certificate. On error it
	// returns the drift condition reason the driver should mark.
	Fetch(ctx context.Context, cert *cmapi.Certificate, ref string) (*FetchResult, string, error)
	// PostWrite runs after every target-namespace Secret write succeeds,
	// before the written data is re-verified. Return nil for providers
	// with nothing to do here.
	PostWrite(ctx context.Context, cert *cmapi.Certificate) error
}

// CertSyncer runs the shared Reconcile skeleton against a CertSource.
type CertSyncer struct {
	client.Client
	Scheme *runtime.Scheme
	Source CertSource
}

func certSyncPtr[T any](v T) *T { return &v }

func (r *CertSyncer) setReady(ctx context.Context, cert *cmapi.Certificate, ok bool, reason, msg string) error {
	original := cert.DeepCopy()
	SetReady(cert, ok, reason, msg)
	return r.Status().Patch(ctx, cert, client.MergeFrom(original))
}

func (r *CertSyncer) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var cert cmapi.Certificate
	if err := r.Get(ctx, req.NamespacedName, &cert); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	ref, ok := cert.GetAnnotations()[r.Source.AnnotationKey()]
	if !ok || ref == "" {
		return ctrl.Result{}, nil
	}
	if !cert.DeletionTimestamp.IsZero() {
		if controllerutil.ContainsFinalizer(&cert, FinalizerName) {
			controllerutil.RemoveFinalizer(&cert, FinalizerName)
			if err := r.Update(ctx, &cert); err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{}, nil
	}
	if !controllerutil.ContainsFinalizer(&cert, FinalizerName) {
		controllerutil.AddFinalizer(&cert, FinalizerName)
		if err := r.Update(ctx, &cert); err != nil {
			return ctrl.Result{}, err
		}
	}

	result, reason, err := r.Source.Fetch(ctx, &cert, ref)
	if err != nil {
		_ = MarkCertDrift(ctx, r.Client, &cert, reason, err.Error())
		return RequeueAfterError(ctx, err, r.Source.Prefix()+": fetch",
			"cert", req.String(), r.Source.AnnotationKey(), ref), nil
	}

	tlsCrt := NormalizePEM(append(append([]byte{}, result.LeafPEM...), result.ChainPEM...))
	tlsCrt = CompleteChain(tlsCrt)
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:        cert.Spec.SecretName,
			Namespace:   cert.Namespace,
			Annotations: map[string]string{},
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			corev1.TLSCertKey:       tlsCrt,
			corev1.TLSPrivateKeyKey: result.KeyPEM,
		},
	}
	secret.Annotations["cert-manager.io/issuer-name"] = cert.Spec.IssuerRef.Name
	secret.Annotations["cert-manager.io/issuer-kind"] = cert.Spec.IssuerRef.Kind
	secret.Annotations["cert-manager.io/issuer-group"] = cert.Spec.IssuerRef.Group
	secret.Annotations[AnnotationSourceHash] = SourceHash(result.LeafPEM, result.KeyPEM, result.ChainPEM)
	secret.Annotations[r.Source.AnnotationKey()] = ref
	secret.Annotations[AnnotationLastSyncTime] = time.Now().UTC().Format(time.RFC3339)
	secret.Annotations[AnnotationChain] = ChainComposition(tlsCrt)
	for k, v := range CertAnnotations(result.LeafPEM) {
		secret.Annotations[k] = v
	}
	for k, v := range result.ExtraAnnotations {
		secret.Annotations[k] = v
	}

	keystoreExisting := &corev1.Secret{}
	keystoreGetErr := r.Get(ctx, types.NamespacedName{Name: cert.Spec.SecretName, Namespace: cert.Namespace}, keystoreExisting)
	if apierrors.IsNotFound(keystoreGetErr) {
		keystoreExisting = nil
	} else if keystoreGetErr != nil {
		_ = MarkCertDrift(ctx, r.Client, &cert, "SecretReadFailed", keystoreGetErr.Error())
		return RequeueAfterError(ctx, keystoreGetErr, r.Source.Prefix()+": read existing secret for keystore build",
			"cert", req.String()), nil
	}

	// Split from tlsCrt (not result.LeafPEM/ChainPEM) so the keystore gets
	// whatever CompleteChain added — otherwise the JKS/PKCS12 silently miss
	// the root that tls.crt just gained.
	keystoreLeaf, keystoreChain := keystore.SplitLeafAndChain(tlsCrt)
	jks, p12, pw, skipped, err := BuildKeystore(keystoreLeaf, result.KeyPEM, keystoreChain,
		keystoreExisting, secret.Annotations[AnnotationSourceHash])
	if err != nil {
		_ = MarkCertDrift(ctx, r.Client, &cert, "KeystoreBuildFailed", err.Error())
		// fall through — TLS half still ships; keystore drift visible on next reconcile.
	} else if skipped {
		_ = MarkCertDrift(ctx, r.Client, &cert, "KeystoreSkipped", r.Source.Prefix()+": source lacks private key; JKS/PKCS12 not generated")
	} else {
		secret.Data["keystore.jks"] = jks
		secret.Data["keystore.p12"] = p12
		secret.Data["keystore.password"] = pw
	}

	if err := VerifySecretData(secret.Data); err != nil {
		_ = MarkCertDrift(ctx, r.Client, &cert, "SecretVerifyFailed", err.Error())
		return RequeueAfterError(ctx, err, r.Source.Prefix()+": verify secret data",
			"cert", req.String()), nil
	}

	targets, err := TargetNamespaces(ctx, r.Client, &cert, result.NamespaceFilter)
	if err != nil {
		_ = MarkCertDrift(ctx, r.Client, &cert, "NamespaceListFailed", err.Error())
		return RequeueAfterError(ctx, fmt.Errorf("list namespaces: %w", err), r.Source.Prefix()+": list namespaces",
			"cert", req.String()), nil
	}

	// Attempt every target namespace even if an earlier one fails — a
	// transient error writing to one namespace must not leave the rest of
	// the fan-out stale with pre-drift cert data until the next reconcile.
	var writeErr error
	var failedNS string
	for _, ns := range targets {
		desired := secret.DeepCopy()
		desired.Namespace = ns
		if ns == cert.Namespace {
			if err := controllerutil.SetControllerReference(&cert, desired, r.Scheme); err != nil {
				// Fall back to non-blocking owner ref — works for cluster-scoped issuers.
				desired.OwnerReferences = []metav1.OwnerReference{{
					APIVersion:         "cert-manager.io/v1",
					Kind:               "Certificate",
					Name:               cert.Name,
					UID:                cert.UID,
					Controller:         certSyncPtr(true),
					BlockOwnerDeletion: certSyncPtr(true),
				}}
			}
		}
		if err := WriteSecret(ctx, r.Client, desired); err != nil && writeErr == nil {
			writeErr, failedNS = err, ns
		}
	}
	if writeErr != nil {
		_ = MarkCertDrift(ctx, r.Client, &cert, "SecretWriteFailed", writeErr.Error())
		return RequeueAfterError(ctx, writeErr, r.Source.Prefix()+": write secret",
			"cert", req.String(), "namespace", failedNS), nil
	}

	if err := r.Source.PostWrite(ctx, &cert); err != nil {
		return RequeueAfterError(ctx, err, r.Source.Prefix()+": post-write", "cert", req.String()), nil
	}

	_ = ClearCertDrift(ctx, r.Client, &cert, "Synced", r.Source.Prefix()+": certificate synced")
	if err := r.setReady(ctx, &cert, true, "Synced", r.Source.Prefix()+": certificate synced"); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: result.ResyncInterval}, nil
}
