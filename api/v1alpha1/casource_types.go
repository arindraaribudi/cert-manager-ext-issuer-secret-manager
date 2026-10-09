// Package v1alpha1 — CASource CRDs. Three cluster-scoped kinds
// (AWS / GCP / Tencent) that fetch a CA PEM bundle from a cloud Secret
// Manager and write it into a same-cluster Opaque k8s Secret as
// data["ca.crt"], ready for trust-manager to consume.
//
// ponytail: GCPSecretManagerCASourceSpec swaps Region for Project;
// AWS + Tencent share the same shape (Region + optional SecretRef for
// static AK/SK fallback). One status type, one target type shared by all.
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// CASourceTarget names the k8s Secret this controller writes.
// Namespace defaults to "cert-manager" (the trust-manager convention).
// Name is required and follows DNS-1123 label rules.
type CASourceTarget struct {
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern=^[a-z0-9]([-a-z0-9]*[a-z0-9])?$
	// +kubebuilder:default=cert-manager
	Namespace string `json:"namespace,omitempty"`
	// +kubebuilder:validation:Required
	Name string `json:"name"`
}

// CASourceStatus is the common status block for all three CASource kinds.
type CASourceStatus struct {
	Conditions   []metav1.Condition `json:"conditions,omitempty"`
	SourceHash   string             `json:"sourceHash,omitempty"`
	LastSyncTime string             `json:"lastSyncTime,omitempty"`
}

// --- AWS ---

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,path=awssecretmanagercasources,shortName=awscas,singular=awssecretmanagercasource
type AWSSecretManagerCASource struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              AWSSecretManagerCASourceSpec `json:"spec,omitempty"`
	Status            CASourceStatus               `json:"status,omitempty"`
}

type AWSSecretManagerCASourceSpec struct {
	// +kubebuilder:validation:Required
	Region string `json:"region"`
	// SecretRef points at a k8s Secret with access-key-id + secret-access-key
	// keys. Nil → SDK default chain (IRSA / Pod Identity).
	SecretRef *SecretRef `json:"secretRef,omitempty"`
	// Endpoint overrides the SDK's region-based default. Empty for AWS.
	Endpoint string `json:"endpoint,omitempty"`
	// +kubebuilder:validation:Required
	SecretName string `json:"secretName"`
	// +kubebuilder:validation:Required
	Target         CASourceTarget  `json:"target"`
	ResyncInterval metav1.Duration `json:"resyncInterval,omitempty"`
}

// +kubebuilder:object:root=true
type AWSSecretManagerCASourceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AWSSecretManagerCASource `json:"items"`
}

// --- GCP ---

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,path=gcpsecretmanagercasources,shortName=gcpcas,singular=gcpsecretmanagercasource
type GCPSecretManagerCASource struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              GCPSecretManagerCASourceSpec `json:"spec,omitempty"`
	Status            CASourceStatus               `json:"status,omitempty"`
}

type GCPSecretManagerCASourceSpec struct {
	// +kubebuilder:validation:Required
	Project string `json:"project"`
	// ADC chain (WI / GKE metadata / static JSON). SecretRef not yet
	// surfaced for GCP — add when a user asks.
	Endpoint string `json:"endpoint,omitempty"`
	// +kubebuilder:validation:Required
	SecretName string `json:"secretName"`
	// +kubebuilder:validation:Required
	Target         CASourceTarget  `json:"target"`
	ResyncInterval metav1.Duration `json:"resyncInterval,omitempty"`
}

// +kubebuilder:object:root=true
type GCPSecretManagerCASourceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []GCPSecretManagerCASource `json:"items"`
}

// --- Tencent ---

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,path=tencentsecretmanagercasources,shortName=tencentcas,singular=tencentsecretmanagercasource
type TencentSecretManagerCASource struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              TencentSecretManagerCASourceSpec `json:"spec,omitempty"`
	Status            CASourceStatus                  `json:"status,omitempty"`
}

type TencentSecretManagerCASourceSpec struct {
	// +kubebuilder:validation:Required
	Region string `json:"region"`
	// SecretRef → static AK/SK fallback. Nil when running on TKE with
	// ServiceAccount annotation eks.tke.cloud.tencent.com/role-arn (SDK
	// detects TKE OIDC env and ignores SecretRef).
	SecretRef *SecretRef `json:"secretRef,omitempty"`
	// Endpoint overrides the intl-en SDK's ssm.intl.tencentcloudapi.com
	// default. Empty for intl; CN users can set ssm.tencentcloudapi.com.
	Endpoint string `json:"endpoint,omitempty"`
	// +kubebuilder:validation:Required
	SecretName string `json:"secretName"`
	// +kubebuilder:validation:Required
	Target         CASourceTarget  `json:"target"`
	ResyncInterval metav1.Duration `json:"resyncInterval,omitempty"`
}

// +kubebuilder:object:root=true
type TencentSecretManagerCASourceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []TencentSecretManagerCASource `json:"items"`
}
