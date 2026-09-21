package options

import (
	"github.com/anchore/clio"
	"github.com/anchore/syft/syft/pkg/cataloger/intoto"
)

type inTotoConfig struct {
	AttestationTypes []string `json:"attestation-types" yaml:"attestation-types" mapstructure:"attestation-types"`
	ExcludePaths     []string `json:"exclude-paths" yaml:"exclude-paths" mapstructure:"exclude-paths"`
}

func defaultInTotoConfig() inTotoConfig {
	def := intoto.DefaultCatalogerConfig()
	return inTotoConfig{
		AttestationTypes: def.AttestationTypes,
		ExcludePaths:     def.ExcludePaths,
	}
}

var _ interface {
	clio.FieldDescriber
} = (*inTotoConfig)(nil)

func (o *inTotoConfig) DescribeFields(descriptions clio.FieldDescriptionSet) {
	descriptions.Add(&o.AttestationTypes, `the in-toto attestation types to derive packages from (default: material, command-run, product, network-trace)`)
	descriptions.Add(&o.ExcludePaths, `glob patterns for attested paths to ignore when deriving packages`)
}
