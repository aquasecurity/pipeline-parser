package models

import (
	loadersUtils "github.com/aquasecurity/pipeline-parser/pkg/loaders/utils"
	"github.com/aquasecurity/pipeline-parser/pkg/models"
	"gopkg.in/yaml.v3"
)

type Workflow struct {
	Triggers      *Triggers      `yaml:"triggers,omitempty"`
	Jobs          []*WorkflowJob `yaml:"jobs,omitempty"`
	When          string         `yaml:"when,omitempty"` // "always", "on_success", "on_fail"
	FileReference *models.FileReference
}

type Triggers struct {
	Schedule *Schedule `yaml:"schedule,omitempty"`
}

type Schedule struct {
	Cron    string   `yaml:"cron"`
	Filters *Filters `yaml:"filters,omitempty"`
}

type Filters struct {
	Branches *Filter `yaml:"branches,omitempty"`
	Tags     *Filter `yaml:"tags,omitempty"`
}

type Filter struct {
	Only   []string `yaml:"only,omitempty"`
	Ignore []string `yaml:"ignore,omitempty"`
}

type WorkflowJob struct {
	job           interface{} // Can be string (job name) or map with job details - unexported to avoid YAML unmarshaling issues
	FileReference *models.FileReference
}

// GetJob returns the job data (string or map)
func (w *WorkflowJob) GetJob() interface{} {
	return w.job
}

func (w *WorkflowJob) UnmarshalYAML(node *yaml.Node) error {
	w.FileReference = loadersUtils.GetFileReference(node)

	// If it's a string, store it directly
	if node.Tag == "!!str" {
		w.job = node.Value
		return nil
	}

	// If it's a map, decode it as a map
	if node.Tag == "!!map" {
		var jobMap map[string]interface{}
		if err := node.Decode(&jobMap); err != nil {
			return err
		}
		w.job = jobMap
		return nil
	}

	// Try to decode as generic interface{}
	var jobData interface{}
	if err := node.Decode(&jobData); err != nil {
		return err
	}
	w.job = jobData
	return nil
}

// WorkflowJobDetails represents a job in a workflow with additional configuration
type WorkflowJobDetails struct {
	JobName  string                 `yaml:"-"`
	Requires []string               `yaml:"requires,omitempty"`
	Context  []string               `yaml:"context,omitempty"`
	Type     string                 `yaml:"type,omitempty"` // "approval"
	Filters  *WorkflowJobFilters    `yaml:"filters,omitempty"`
	Matrix   map[string]interface{} `yaml:"matrix,omitempty"`
}

type WorkflowJobFilters struct {
	Branches *Filter `yaml:"branches,omitempty"`
	Tags     *Filter `yaml:"tags,omitempty"`
}
