// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
)

// TencentCertificateIssuerSpec describes how to fetch an issued cert from
// Tencent SSL. ponytail: SecretRef keys are secret-id + secret-key (matches
// Tencent SDK convention; static fallback only — pod identity is the
// TKE OIDC chain).
type TencentCertificateIssuerSpec struct {
	Region         string            `json:"region"`
	SecretRef      *TencentSecretRef `json:"secretRef,omitempty"`
	Endpoint       string            `json:"endpoint,omitempty"`
	ResyncInterval metav1.Duration   `json:"resyncInterval,omitempty"` // +kubebuilder:default="12h"
}

// TencentSecretRef references a k8s Secret holding TENCENTCLOUD_SECRET_ID
// and TENCENTCLOUD_SECRET_KEY values.
type TencentSecretRef struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
}

type TencentCertificateIssuerStatus struct {
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
type TencentCertificateIssuer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              TencentCertificateIssuerSpec   `json:"spec,omitempty"`
	Status            TencentCertificateIssuerStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
type TencentCertificateIssuerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []TencentCertificateIssuer `json:"items"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,path=tencentcertificateclusterissuers,shortName=tencentcertclusterissuer,categories=cert-manager
type TencentCertificateClusterIssuer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              TencentCertificateIssuerSpec   `json:"spec,omitempty"`
	Status            TencentCertificateIssuerStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
type TencentCertificateClusterIssuerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []TencentCertificateClusterIssuer `json:"items"`
}

func (i *TencentCertificateIssuer) GetConditions() []metav1.Condition {
	return i.Status.Conditions
}
func (i *TencentCertificateIssuer) SetConditions(c []metav1.Condition) {
	i.Status.Conditions = c
}
func (i *TencentCertificateClusterIssuer) GetConditions() []metav1.Condition {
	return i.Status.Conditions
}
func (i *TencentCertificateClusterIssuer) SetConditions(c []metav1.Condition) {
	i.Status.Conditions = c
}

// GetNamespace returns the Secret's namespace, falling back to defaultNS.
// ponytail: empty string means "use the certificate's namespace" — the
// calling reconciler passes cert.Namespace as defaultNS.
func (r *TencentSecretRef) GetNamespace(defaultNS string) string {
	if r == nil || r.Namespace == "" {
		return defaultNS
	}
	return r.Namespace
}

var _ runtime.Object = (*TencentCertificateIssuer)(nil)
