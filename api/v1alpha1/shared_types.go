package v1alpha1

// SecretRef references a Kubernetes Secret holding provider credentials.
// ponytail: empty Namespace is resolved by the controller (Certificate ns for
// Issuer, --cert-manager-namespace flag for ClusterIssuer).
type SecretRef struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
}

// NamespaceFilter controls which namespaces a ClusterIssuer's Secret fans
// out to. Ignored by namespaced Issuers (always just the Certificate's ns).
// Allow takes precedence: if non-empty, only listed namespaces are targeted.
// Otherwise Deny excludes listed namespaces from the fan-out. Neither set
// (the default) fans out to every non-terminating namespace.
type NamespaceFilter struct {
	Allow []string `json:"allow,omitempty"`
	Deny  []string `json:"deny,omitempty"`
}

// IssuerConfig bundles the per-Issuer settings the reconciler needs, read
// once from the Issuer/ClusterIssuer object.
type IssuerConfig struct {
	PayloadKeys     PayloadKeys     `json:"payloadKeys,omitempty"`
	NamespaceFilter NamespaceFilter `json:"namespaceFilter,omitempty"`
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
