package models

import (
	"github.com/aquasecurity/pipeline-parser/pkg/models"
)

type Job struct {
	Type             string                 `yaml:"type,omitempty"` // "build", "release", "lock", "unlock", "approval", "no-op"
	Description      string                 `yaml:"description,omitempty"`
	Parallelism      interface{}           `yaml:"parallelism,omitempty"` // int or string parameter
	Steps            []*Step                `yaml:"steps,omitempty"`
	WorkingDirectory string                 `yaml:"working_directory,omitempty"`
	Shell            interface{}            `yaml:"shell,omitempty"` // string or []string
	Environment      interface{}           `yaml:"environment,omitempty"` // map, array, or string
	ResourceClass    string                 `yaml:"resource_class,omitempty"`
	Docker           []*DockerExecutor     `yaml:"docker,omitempty"`
	Machine          *MachineExecutor       `yaml:"machine,omitempty"`
	MacOS            *MacOSExecutor         `yaml:"macos,omitempty"`
	Parameters       map[string]*Parameter  `yaml:"parameters,omitempty"`
	// Release job specific
	PlanName         string                 `yaml:"plan_name,omitempty"`
	// Lock/Unlock job specific
	Key              string                 `yaml:"key,omitempty"`
	FileReference    *models.FileReference
}

