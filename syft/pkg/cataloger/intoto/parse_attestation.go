package intoto

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/sbomit/sbomit/pkg/resolve"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

type attestationParser struct {
	cfg CatalogerConfig
}

func newAttestationParser(cfg CatalogerConfig) attestationParser {
	return attestationParser{cfg: cfg}
}

func (p attestationParser) parseAttestation(_ context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to read attestation file %q: %w", reader.RealPath, err)
	}

	if !isInTotoAttestation(data) {
		log.WithFields("path", reader.RealPath).Trace("file is not an in-toto attestation")
		return nil, nil, nil
	}

	result, err := resolve.Resolve(data, resolve.Options{
		AttestationTypes: p.cfg.AttestationTypes,
		ExcludePaths:     p.cfg.ExcludePaths,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("unable to resolve attestation %q: %w", reader.RealPath, err)
	}

	if result == nil {
		return nil, nil, nil
	}

	var pkgs []pkg.Package
	var relationships []artifact.Relationship

	for _, resolved := range result.Packages {
		syftPkg := newPackage(resolved, result, reader)
		if syftPkg == nil {
			continue
		}

		pkgs = append(pkgs, *syftPkg)

		relationships = append(relationships, artifact.Relationship{
			From: *syftPkg,
			To:   reader.Coordinates,
			Type: artifact.EvidentByRelationship,
		})
	}

	return pkgs, relationships, nil
}

func isInTotoAttestation(data []byte) bool {
	if !json.Valid(data) {
		return false
	}

	var envelope struct {
		Type        string          `json:"_type"`
		PayloadType string          `json:"payloadType"`
		Payload     json.RawMessage `json:"payload"`
		Predicate   json.RawMessage `json:"predicate"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return false
	}

	if len(envelope.Predicate) > 0 && strings.Contains(envelope.Type, "in-toto.io/Statement") {
		return true
	}

	return len(envelope.Payload) > 0 && strings.Contains(envelope.PayloadType, "in-toto")
}
