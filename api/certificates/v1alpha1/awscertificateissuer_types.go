// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"

	api "github.com/arindraaribudi/cert-manager-ext-issuer-secret-manager/api/v1alpha1"
)

// AWSCertificateIssuerSpec describes how to fetch an issued cert from ACM.
// ponytail: empty SecretRef → IRSA pod-identity chain; static path stays
// available for non-EKS clusters. NamespaceFilter only applies to
// ClusterIssuer kinds; namespaced Issuers ignore it (always one ns).
type AWSCertificateIssuerSpec struct {
	Region          string                `json:"region"`
	SecretRef       *AWSSecretRef         `json:"secretRef,omitempty"`
	Endpoint        string                `json:"endpoint,omitempty"`
	NamespaceFilter *api.NamespaceFilter  `json:"namespaceFilter,omitempty"`
	ResyncInterval  metav1.Duration       `json:"resyncInterval,omitempty"` // +kubebuilder:default="12h"
}

// AWSSecretRef references a k8s Secret holding static AWS keys.
// Keys: access-key-id, secret-access-key, session-token (optional),
// passphrase (optional — required for private-key export).
type AWSSecretRef struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
}

type AWSCertificateIssuerStatus struct {
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
type AWSCertificateIssuer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              AWSCertificateIssuerSpec   `json:"spec,omitempty"`
	Status            AWSCertificateIssuerStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
type AWSCertificateIssuerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AWSCertificateIssuer `json:"items"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,path=awscertificateclusterissuers,shortName=awscertclusterissuer,categories=cert-manager
type AWSCertificateClusterIssuer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              AWSCertificateIssuerSpec   `json:"spec,omitempty"`
	Status            AWSCertificateIssuerStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
type AWSCertificateClusterIssuerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AWSCertificateClusterIssuer `json:"items"`
}

func (i *AWSCertificateIssuer) GetConditions() []metav1.Condition {
	return i.Status.Conditions
}
func (i *AWSCertificateIssuer) SetConditions(c []metav1.Condition) {
	i.Status.Conditions = c
}
func (i *AWSCertificateClusterIssuer) GetConditions() []metav1.Condition {
	return i.Status.Conditions
}
func (i *AWSCertificateClusterIssuer) SetConditions(c []metav1.Condition) {
	i.Status.Conditions = c
}

// GetNamespace returns the SecretRef's namespace, falling back to the
// supplied default (typically the Certificate's namespace).
func (r *AWSSecretRef) GetNamespace(defaultNS string) string {
	if r == nil || r.Namespace == "" {
		return defaultNS
	}
	return r.Namespace
}

var _ runtime.Object = (*AWSCertificateIssuer)(nil)
