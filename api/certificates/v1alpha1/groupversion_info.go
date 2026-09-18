// +kubebuilder:object:generate=true
// +groupName=certificates.cert-manager.io
package v1alpha1

import (
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/scheme"
)

var (
	SchemeGroupVersion = schema.GroupVersion{Group: "certificates.cert-manager.io", Version: "v1alpha1"}
)

var (
	SchemeBuilder = &scheme.Builder{GroupVersion: SchemeGroupVersion}
	AddToScheme   = SchemeBuilder.AddToScheme
)

func init() {
	SchemeBuilder.Register(
		&AWSCertificateIssuer{}, &AWSCertificateIssuerList{},
		&AWSCertificateClusterIssuer{}, &AWSCertificateClusterIssuerList{},
		&TencentCertificateIssuer{}, &TencentCertificateIssuerList{},
		&TencentCertificateClusterIssuer{}, &TencentCertificateClusterIssuerList{},
	)
}