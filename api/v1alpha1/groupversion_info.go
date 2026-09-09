// +kubebuilder:object:generate=true
// +groupName=secret-manager.cert-manager.io
package v1alpha1

import (
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/scheme"
)

var (
	SchemeGroupVersion = schema.GroupVersion{Group: "secret-manager.cert-manager.io", Version: "v1alpha1"}
)

var (
	SchemeBuilder = &scheme.Builder{}
	AddToScheme   = SchemeBuilder.AddToScheme
)

func init() {
	SchemeBuilder.Register(
		// AWS
		&AWSSecretManagerIssuer{}, &AWSSecretManagerIssuerList{},
		&AWSSecretManagerClusterIssuer{}, &AWSSecretManagerClusterIssuerList{},
		// GCP
		&GCPSecretManagerIssuer{}, &GCPSecretManagerIssuerList{},
		&GCPSecretManagerClusterIssuer{}, &GCPSecretManagerClusterIssuerList{},
		// Tencent
		&TencentSecretManagerIssuer{}, &TencentSecretManagerIssuerList{},
		&TencentSecretManagerClusterIssuer{}, &TencentSecretManagerClusterIssuerList{},
	)
}
