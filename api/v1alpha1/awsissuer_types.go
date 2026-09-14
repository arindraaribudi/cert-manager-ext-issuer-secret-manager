package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,path=awssecretmanagerissuers,shortName=awssmi,singular=awssecretmanagerissuer
type AWSSecretManagerIssuer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              AWSSecretManagerIssuerSpec   `json:"spec,omitempty"`
	Status            AWSSecretManagerIssuerStatus `json:"status,omitempty"`
}

type AWSSecretManagerIssuerSpec struct {
	Region          string          `json:"region"`
	SecretRef       *SecretRef      `json:"secretRef,omitempty"`
	PayloadKeys     PayloadKeys     `json:"payloadKeys,omitempty"`
	NamespaceFilter NamespaceFilter `json:"namespaceFilter,omitempty"`
}

type AWSSecretManagerIssuerStatus struct {
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
type AWSSecretManagerIssuerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AWSSecretManagerIssuer `json:"items"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,path=awssecretmanagerclusterissuers,shortName=awssmci,singular=awssecretmanagerclusterissuer
type AWSSecretManagerClusterIssuer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              AWSSecretManagerIssuerSpec   `json:"spec,omitempty"`
	Status            AWSSecretManagerIssuerStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
type AWSSecretManagerClusterIssuerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AWSSecretManagerClusterIssuer `json:"items"`
}
