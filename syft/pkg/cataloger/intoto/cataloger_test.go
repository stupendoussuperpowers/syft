package intoto

import (
	"testing"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func Test_parseAttestation(t *testing.T) {
	fixture := "testdata/witness.attestation.json"
	location := file.NewLocation(fixture)

	expectedPkgs := []pkg.Package{
		{
			Name:      "github.com/spf13/cobra",
			Version:   "v1.8.0",
			Type:      pkg.GoModulePkg,
			Language:  pkg.Go,
			FoundBy:   catalogerName,
			Locations: file.NewLocationSet(location),
			PURL:      "pkg:golang/github.com/spf13/cobra@v1.8.0",
			Metadata: pkg.InTotoAttestationEntry{
				Ecosystem:  "golang",
				ResolvedBy: "attestation:go",
				Digests: []file.Digest{
					{Algorithm: "sha256", Value: "2c0b1a0c6bd1b4e0f1b7e8a0d0a0d4c58dd8bde6c9a0f7d6dbcb70b6e2f1a9c4"},
				},
			},
		},
		{
			Name:      "requests",
			Version:   "2.31.0",
			Type:      pkg.PythonPkg,
			Language:  pkg.Python,
			FoundBy:   catalogerName,
			Locations: file.NewLocationSet(location),
			PURL:      "pkg:pypi/requests@2.31.0",
			Metadata: pkg.InTotoAttestationEntry{
				Ecosystem:  "pypi",
				ResolvedBy: "attestation:python",
				Digests: []file.Digest{
					{Algorithm: "sha256", Value: "1f0b1a0c6bd1b4e0f1b7e8a0d0a0d4c58dd8bde6c9a0f7d6dbcb70b6e2f1a9c3"},
				},
			},
		},
	}

	var expectedRelationships []artifact.Relationship
	for _, p := range expectedPkgs {
		expectedRelationships = append(expectedRelationships, artifact.Relationship{
			From: p,
			To:   location.Coordinates,
			Type: artifact.EvidentByRelationship,
		})
	}

	pkgtest.NewCatalogTester().
		FromFile(t, fixture).
		Expects(expectedPkgs, expectedRelationships).
		TestParser(t, newAttestationParser(DefaultCatalogerConfig()).parseAttestation)
}

func Test_parseAttestation_ignoresNonAttestations(t *testing.T) {
	pkgtest.NewCatalogTester().
		FromFile(t, "testdata/not-an-attestation.json").
		Expects(nil, nil).
		TestParser(t, newAttestationParser(DefaultCatalogerConfig()).parseAttestation)
}

func Test_Cataloger_Globs(t *testing.T) {
	pkgtest.NewCatalogTester().
		FromDirectory(t, "testdata/glob-paths").
		ExpectsResolverContentQueries([]string{
			"app.intoto.json",
			"app.attestation.json",
			"app.att",
			"app.dsse.json",
			"attestation.json",
		}).
		TestCataloger(t, NewCataloger(DefaultCatalogerConfig()))
}
