package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,path=tencentsecretmanagerissuers,shortName=tencentsmi,singular=tencentsecretmanagerissuer
type TencentSecretManagerIssuer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              TencentSecretManagerIssuerSpec   `json:"spec,omitempty"`
	Status            TencentSecretManagerIssuerStatus `json:"status,omitempty"`
}

type TencentSecretManagerIssuerSpec struct {
	Region      string      `json:"region"`
	SecretRef   *SecretRef  `json:"secretRef,omitempty"`
	PayloadKeys PayloadKeys `json:"payloadKeys,omitempty"`
}

type TencentSecretManagerIssuerStatus struct {
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
type TencentSecretManagerIssuerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []TencentSecretManagerIssuer `json:"items"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,path=tencentsecretmanagerclusterissuers,shortName=tencentsmci,singular=tencentsecretmanagerclusterissuer
type TencentSecretManagerClusterIssuer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              TencentSecretManagerIssuerSpec   `json:"spec,omitempty"`
	Status            TencentSecretManagerIssuerStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
type TencentSecretManagerClusterIssuerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []TencentSecretManagerClusterIssuer `json:"items"`
}
