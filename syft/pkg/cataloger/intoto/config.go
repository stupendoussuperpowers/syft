package intoto

// CatalogerConfig mirrors the knobs that sbomit's resolver exposes, so that attestation
// ingestion can be tuned the same way from syft's application config.
type CatalogerConfig struct {
	// AttestationTypes are the witness attestation types to consider. When empty sbomit's
	// defaults are used (material, command-run, product, network-trace).
	// app-config: in-toto.attestation-types
	AttestationTypes []string `yaml:"attestation-types" json:"attestation-types" mapstructure:"attestation-types"`

	// ExcludePaths are filepath.Match globs applied to attested paths, on top of the
	// built-in filtering that sbomit already does for caches and build scratch.
	// app-config: in-toto.exclude-paths
	ExcludePaths []string `yaml:"exclude-paths" json:"exclude-paths" mapstructure:"exclude-paths"`
}

func DefaultCatalogerConfig() CatalogerConfig {
	return CatalogerConfig{}
}

func (c CatalogerConfig) WithAttestationTypes(types []string) CatalogerConfig {
	c.AttestationTypes = types
	return c
}

func (c CatalogerConfig) WithExcludePaths(paths []string) CatalogerConfig {
	c.ExcludePaths = paths
	return c
}
