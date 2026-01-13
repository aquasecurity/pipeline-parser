package models

import (
	"github.com/aquasecurity/pipeline-parser/pkg/models"
)

type Config struct {
	Version   interface{}            `yaml:"version"` // Can be "2.1" or 2.1
	Orbs      map[string]interface{} `yaml:"orbs,omitempty"`
	Commands  map[string]*Command     `yaml:"commands,omitempty"`
	Executors map[string]*Executor   `yaml:"executors,omitempty"`
	Jobs      map[string]*Job        `yaml:"jobs,omitempty"`
	Workflows map[string]*Workflow   `yaml:"workflows,omitempty"`
	Parameters *Parameters            `yaml:"parameters,omitempty"`
}

type Command struct {
	Steps      []*Step                `yaml:"steps"`
	Parameters map[string]*Parameter  `yaml:"parameters,omitempty"`
	Description string                `yaml:"description,omitempty"`
	FileReference *models.FileReference
}

type Executor struct {
	Docker      []*DockerExecutor     `yaml:"docker,omitempty"`
	Machine     *MachineExecutor      `yaml:"machine,omitempty"`
	MacOS       *MacOSExecutor        `yaml:"macos,omitempty"`
	ResourceClass string              `yaml:"resource_class,omitempty"`
	Shell       interface{}           `yaml:"shell,omitempty"` // string or []string
	Environment interface{}           `yaml:"environment,omitempty"` // map or array
	WorkingDirectory string           `yaml:"working_directory,omitempty"`
	FileReference *models.FileReference
}

type DockerExecutor struct {
	Image      string                 `yaml:"image"`
	Name       string                 `yaml:"name,omitempty"`
	Entrypoint interface{}           `yaml:"entrypoint,omitempty"` // string or []string
	Command    interface{}           `yaml:"command,omitempty"` // string or []string
	User       string                 `yaml:"user,omitempty"`
	Environment interface{}          `yaml:"environment,omitempty"` // map, array, or string
	AwsAuth    *AwsAuth              `yaml:"aws_auth,omitempty"`
	Auth       *Auth                 `yaml:"auth,omitempty"`
}

type MachineExecutor struct {
	Image          string                 `yaml:"image,omitempty"`
	DockerLayerCaching interface{}        `yaml:"docker_layer_caching,omitempty"` // bool or string parameter
	ResourceClass  string                 `yaml:"resource_class,omitempty"`
	Shell          interface{}            `yaml:"shell,omitempty"` // string or []string
}

type MacOSExecutor struct {
	Xcode          interface{}           `yaml:"xcode"` // string or number
	ResourceClass  string                `yaml:"resource_class,omitempty"`
	Shell          interface{}           `yaml:"shell,omitempty"` // string or []string
}

type AwsAuth struct {
	AwsAccessKeyId     string `yaml:"aws_access_key_id,omitempty"`
	AwsSecretAccessKey string `yaml:"aws_secret_access_key,omitempty"`
	OidcRoleArn        string `yaml:"oidc_role_arn,omitempty"`
}

type Auth struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

type Parameters struct {
	Parameters map[string]*Parameter `yaml:",inline"`
}

type Parameter struct {
	Type        string      `yaml:"type"` // "boolean", "string", "enum", "integer", "steps", "executor", "env_var_name"
	Default     interface{} `yaml:"default,omitempty"`
	Description string      `yaml:"description,omitempty"`
	Enum        []string    `yaml:"enum,omitempty"`
	FileReference *models.FileReference
}

