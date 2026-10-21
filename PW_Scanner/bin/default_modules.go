package bin

import (
	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/modules/fuzzing"
)

// NewModuleSetWithDefaults exposes the PW Scanner probe/identifier module.
func NewModuleSetWithDefaults() zgrab2.ModuleSet {
	return zgrab2.ModuleSet{"fuzzing": &fuzzing.Module{}}
}
