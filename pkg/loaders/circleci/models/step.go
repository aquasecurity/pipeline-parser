package models

import (
	loadersUtils "github.com/aquasecurity/pipeline-parser/pkg/loaders/utils"
	"github.com/aquasecurity/pipeline-parser/pkg/models"
	"gopkg.in/yaml.v3"
)

type Step struct {
	step          interface{} // Can be string (command/orb reference) or map - unexported to avoid YAML unmarshaling issues
	FileReference *models.FileReference
}

// GetStep returns the step data (string or map)
func (s *Step) GetStep() interface{} {
	return s.step
}

func (s *Step) UnmarshalYAML(node *yaml.Node) error {
	s.FileReference = loadersUtils.GetFileReference(node)

	// If it's a string, store it directly
	if node.Tag == "!!str" {
		s.step = node.Value
		return nil
	}

	// If it's a map, decode it as a map
	if node.Tag == "!!map" {
		var stepMap map[string]interface{}
		if err := node.Decode(&stepMap); err != nil {
			return err
		}
		s.step = stepMap
		return nil
	}

	// Try to decode as generic interface{}
	var stepData interface{}
	if err := node.Decode(&stepData); err != nil {
		return err
	}
	s.step = stepData
	return nil
}

// Step types as maps for easier parsing
type RunStep struct {
	Run *RunStepConfig `yaml:"run"`
}

type RunStepConfig struct {
	Command          string      `yaml:"command,omitempty"`
	Name             string      `yaml:"name,omitempty"`
	Shell            interface{} `yaml:"shell,omitempty"`       // string or []string
	Environment      interface{} `yaml:"environment,omitempty"` // map, array, or string
	NoOutputTimeout  string      `yaml:"no_output_timeout,omitempty"`
	When             string      `yaml:"when,omitempty"` // "always", "on_success", "on_fail"
	Background       bool        `yaml:"background,omitempty"`
	WorkingDirectory string      `yaml:"working_directory,omitempty"`
	FileReference    *models.FileReference
}

type CheckoutStep struct {
	Checkout string `yaml:"checkout,omitempty"` // Usually "checkout" or path
}

type SetupRemoteDockerStep struct {
	SetupRemoteDocker *SetupRemoteDockerConfig `yaml:"setup_remote_docker"`
}

type SetupRemoteDockerConfig struct {
	Version            string `yaml:"version,omitempty"`
	DockerLayerCaching bool   `yaml:"docker_layer_caching,omitempty"`
}

type SaveCacheStep struct {
	SaveCache *SaveCacheConfig `yaml:"save_cache"`
}

type SaveCacheConfig struct {
	Key   string   `yaml:"key"`
	Paths []string `yaml:"paths"`
	When  string   `yaml:"when,omitempty"` // "always", "on_success", "on_fail"
}

type RestoreCacheStep struct {
	RestoreCache *RestoreCacheConfig `yaml:"restore_cache"`
}

type RestoreCacheConfig struct {
	Keys []string `yaml:"keys"`
}

type StoreArtifactsStep struct {
	StoreArtifacts *StoreArtifactsConfig `yaml:"store_artifacts"`
}

type StoreArtifactsConfig struct {
	Path        string `yaml:"path"`
	Destination string `yaml:"destination,omitempty"`
}

type StoreTestResultsStep struct {
	StoreTestResults *StoreTestResultsConfig `yaml:"store_test_results"`
}

type StoreTestResultsConfig struct {
	Path string `yaml:"path"`
}

type PersistToWorkspaceStep struct {
	PersistToWorkspace *PersistToWorkspaceConfig `yaml:"persist_to_workspace"`
}

type PersistToWorkspaceConfig struct {
	Root  string   `yaml:"root"`
	Paths []string `yaml:"paths"`
}

type AttachWorkspaceStep struct {
	AttachWorkspace *AttachWorkspaceConfig `yaml:"attach_workspace"`
}

type AttachWorkspaceConfig struct {
	At string `yaml:"at"`
}

type AddSSHKeysStep struct {
	AddSSHKeys *AddSSHKeysConfig `yaml:"add_ssh_keys"`
}

type AddSSHKeysConfig struct {
	Fingerprints []string `yaml:"fingerprints,omitempty"`
}
