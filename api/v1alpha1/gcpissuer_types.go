package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,path=gcpsecretmanagerissuers,shortName=gcpsmi,singular=gcpsecretmanagerissuer
type GCPSecretManagerIssuer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              GCPSecretManagerIssuerSpec   `json:"spec,omitempty"`
	Status            GCPSecretManagerIssuerStatus `json:"status,omitempty"`
}

type GCPSecretManagerIssuerSpec struct {
	Project         string          `json:"project"`
	SecretRef       *SecretRef      `json:"secretRef,omitempty"`
	PayloadKeys     PayloadKeys     `json:"payloadKeys,omitempty"`
	NamespaceFilter NamespaceFilter `json:"namespaceFilter,omitempty"`
}

type GCPSecretManagerIssuerStatus struct {
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
type GCPSecretManagerIssuerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []GCPSecretManagerIssuer `json:"items"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,path=gcpsecretmanagerclusterissuers,shortName=gcpsmci,singular=gcpsecretmanagerclusterissuer
type GCPSecretManagerClusterIssuer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              GCPSecretManagerIssuerSpec   `json:"spec,omitempty"`
	Status            GCPSecretManagerIssuerStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
type GCPSecretManagerClusterIssuerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []GCPSecretManagerClusterIssuer `json:"items"`
}