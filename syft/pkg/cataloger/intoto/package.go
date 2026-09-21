package intoto

import (
	"sort"

	"github.com/sbomit/sbomit/pkg/resolve"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

// newPackage converts a package that sbomit derived from attested paths into a syft package.
//
// Note that the attested paths describe the build host, not the source being scanned, so the
// package's locations point at the attestation file itself — the only place in this source where
// there is evidence of the package. The build-host paths are preserved in the metadata.
func newPackage(p resolve.Package, result *resolve.Result, reader file.LocationReadCloser) *pkg.Package {
	if p.Name == "" {
		return nil
	}

	metadata := pkg.InTotoAttestationEntry{
		Ecosystem:   p.Ecosystem,
		ResolvedBy:  p.FoundBy,
		Digests:     toDigests(p.Digests),
		DownloadURL: p.DownloadURL,
		DownloadIP:  p.DownloadIP,
		Files:       ownedPaths(result, p.ID),
	}

	syftPkg := pkg.Package{
		Name:    p.Name,
		Version: p.Version,
		FoundBy: catalogerName,
		Locations: file.NewLocationSet(
			reader.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
		),
		Language: pkg.LanguageFromPURL(p.PURL),
		Type:     pkg.TypeFromPURL(p.PURL),
		PURL:     p.PURL,
		Metadata: metadata,
	}

	syftPkg.SetID()

	return &syftPkg
}

func toDigests(digests []resolve.Digest) []file.Digest {
	if len(digests) == 0 {
		return nil
	}

	out := make([]file.Digest, 0, len(digests))
	for _, d := range digests {
		out = append(out, file.Digest{
			Algorithm: d.Algorithm,
			Value:     d.Value,
		})
	}
	return out
}

// ownedPaths returns the attested paths that the given package claims. sbomit does not populate
// per-package relationships yet, so today this is typically empty.
func ownedPaths(result *resolve.Result, packageID string) []string {
	var paths []string
	for _, rel := range result.Relationships {
		if rel.FromPackageID != packageID {
			continue
		}
		paths = append(paths, rel.ToPath)
	}

	sort.Strings(paths)

	return paths
}
