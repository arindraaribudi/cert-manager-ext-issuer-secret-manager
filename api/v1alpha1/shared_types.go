package v1alpha1

// SecretRef references a Kubernetes Secret holding provider credentials.
// ponytail: empty Namespace is resolved by the controller (Certificate ns for
// Issuer, --cert-manager-namespace flag for ClusterIssuer).
type SecretRef struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
}

// PayloadKeys overrides the JSON keys the controller reads from the
// cloud-side secret. Defaults: certificate / private_key / certificate_chain.
type PayloadKeys struct {
	Certificate      string `json:"certificate,omitempty"`
	PrivateKey       string `json:"privateKey,omitempty"`
	CertificateChain string `json:"certificateChain,omitempty"`
}

func (p PayloadKeys) CertificateOrDefault() string {
	if p.Certificate == "" {
		return "certificate"
	}
	return p.Certificate
}

func (p PayloadKeys) PrivateKeyOrDefault() string {
	if p.PrivateKey == "" {
		return "private_key"
	}
	return p.PrivateKey
}

func (p PayloadKeys) CertificateChainOrDefault() string {
	if p.CertificateChain == "" {
		return "certificate_chain"
	}
	return p.CertificateChain
}
