/*
Package intoto provides a concrete Cataloger implementation for packages derived from in-toto
attestations (e.g. witness attestation collections) found within the scanned source.
*/
package intoto

import (
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

const catalogerName = "in-toto-attestation-cataloger"

// NewCataloger returns a cataloger that derives packages from in-toto attestations.
//
// Attestation files have no reserved extension in practice, so the globs are deliberately broad
// and the parser sniffs each candidate before committing to it.
func NewCataloger(cfg CatalogerConfig) pkg.Cataloger {
	parser := newAttestationParser(cfg)
	return generic.NewCataloger(catalogerName).
		WithParserByGlobs(parser.parseAttestation,
			"**/*.intoto.json",
			"**/*.attestation.json",
			"**/*.att",
			"**/*.dsse.json",
			"**/attestation.json",
		)
}
