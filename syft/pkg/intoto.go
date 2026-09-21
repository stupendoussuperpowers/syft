package pkg

import "github.com/anchore/syft/syft/file"

// InTotoAttestationEntry represents a package derived from an in-toto attestation, capturing the
// build-time evidence that the attestation recorded but the scanned source itself cannot show.
type InTotoAttestationEntry struct {
	// Ecosystem is the package ecosystem as reported by the attestation resolver (e.g. pypi, golang).
	Ecosystem string `json:"ecosystem,omitempty"`

	// ResolvedBy names the resolver that derived this package from attested paths.
	ResolvedBy string `json:"resolvedBy,omitempty"`

	// Digests of the package's distributed artifact, when the attestation captured them.
	Digests []file.Digest `json:"digests,omitempty"`

	// DownloadURL is where the package was fetched from, when a network attestation recorded it.
	DownloadURL string `json:"downloadURL,omitempty"`

	// DownloadIP is the address the package was fetched from, when a network attestation recorded it.
	DownloadIP string `json:"downloadIP,omitempty"`

	// Files are the attested paths owned by this package, as absolute paths on the build host.
	Files []string `json:"files,omitempty"`
}
