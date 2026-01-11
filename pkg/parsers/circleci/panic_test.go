package circleci

import (
	"testing"

	circleciModels "github.com/aquasecurity/pipeline-parser/pkg/loaders/circleci/models"
)

// TestParseJobRunner_NoPanicOnNilDockerElement tests that parseJobRunner does not panic when Docker slice contains nil element
// This test proves the fix for the panic that would occur when accessing docker.Image on a nil docker element
func TestParseJobRunner_NoPanicOnNilDockerElement(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Unexpected panic when Docker slice contains nil element (should be fixed): %v", r)
		}
	}()

	job := &circleciModels.Job{
		Docker: []*circleciModels.DockerExecutor{
			nil, // nil element in slice - this used to cause a panic
		},
	}

	runner := parseJobRunner(job)
	if runner == nil {
		t.Error("Expected runner to be returned, got nil")
	}
	// Runner should be empty/default since docker element was nil
	if runner.Type != nil {
		t.Errorf("Expected runner.Type to be nil when docker element is nil, got %v", runner.Type)
	}
}

// TestParseJobRunner_NoPanicOnEmptyDockerSlice tests that parseJobRunner handles empty Docker slice correctly
func TestParseJobRunner_NoPanicOnEmptyDockerSlice(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Unexpected panic when Docker slice is empty: %v", r)
		}
	}()

	job := &circleciModels.Job{
		Docker: []*circleciModels.DockerExecutor{}, // empty slice
	}

	runner := parseJobRunner(job)
	if runner == nil {
		t.Error("Expected runner to be returned, got nil")
	}
}

// TestParseRunStep_NoPanicOnNilShell tests that parseRunStep does not panic when step.Shell is nil but shell type is provided
// This test proves the fix for the panic that would occur when accessing step.Shell.Type when step.Shell is nil
func TestParseRunStep_NoPanicOnNilShell(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Unexpected panic when step.Shell is nil but shell type is provided (should be fixed): %v", r)
		}
	}()

	// Create a run step with shell but no command (this causes step.Shell to be nil initially)
	// This used to cause a panic when trying to set step.Shell.Type
	runData := map[string]interface{}{
		"shell": "/bin/bash",
		// Note: no "command" field, so step.Shell won't be created initially
	}

	step := parseRunStep(runData, nil)
	if step == nil {
		t.Error("Expected step to be returned, got nil")
	}
	// step.Shell should be nil since there's no command
	if step.Shell != nil {
		t.Errorf("Expected step.Shell to be nil when no command is provided, got %v", step.Shell)
	}
}

// TestParseRunStep_WithCommandAndShell tests that parseRunStep correctly handles both command and shell
func TestParseRunStep_WithCommandAndShell(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Unexpected panic: %v", r)
		}
	}()

	runData := map[string]interface{}{
		"command": "echo hello",
		"shell":   "/bin/bash",
	}

	step := parseRunStep(runData, nil)
	if step == nil {
		t.Error("Expected step to be returned, got nil")
	}
	if step.Shell == nil {
		t.Error("Expected step.Shell to be created when command is provided")
	}
	if step.Shell.Script == nil || *step.Shell.Script != "echo hello" {
		t.Errorf("Expected step.Shell.Script to be 'echo hello', got %v", step.Shell.Script)
	}
	if step.Shell.Type == nil || *step.Shell.Type != "/bin/bash" {
		t.Errorf("Expected step.Shell.Type to be '/bin/bash', got %v", step.Shell.Type)
	}
}

// TestParseJobRunner_WithValidDocker tests that parseJobRunner correctly handles valid Docker configuration
func TestParseJobRunner_WithValidDocker(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Unexpected panic: %v", r)
		}
	}()

	image := "cimg/base:current"
	job := &circleciModels.Job{
		Docker: []*circleciModels.DockerExecutor{
			{
				Image: image,
			},
		},
	}

	runner := parseJobRunner(job)
	if runner == nil {
		t.Error("Expected runner to be returned, got nil")
	}
	if runner.Type == nil || *runner.Type != "docker" {
		t.Errorf("Expected runner.Type to be 'docker', got %v", runner.Type)
	}
	if runner.DockerMetadata == nil || runner.DockerMetadata.Image == nil {
		t.Error("Expected runner.DockerMetadata.Image to be set")
	}
	if *runner.DockerMetadata.Image != image {
		t.Errorf("Expected runner.DockerMetadata.Image to be '%s', got %v", image, runner.DockerMetadata.Image)
	}
}

// TestParseJobRunner_WithNilDockerThenValidMachine tests that parseJobRunner falls back to Machine when Docker is nil
func TestParseJobRunner_WithNilDockerThenValidMachine(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Unexpected panic: %v", r)
		}
	}()

	job := &circleciModels.Job{
		Docker: []*circleciModels.DockerExecutor{
			nil, // nil element
		},
		Machine: &circleciModels.MachineExecutor{
			Image: "ubuntu-2004:current",
		},
	}

	runner := parseJobRunner(job)
	if runner == nil {
		t.Error("Expected runner to be returned, got nil")
	}
	if runner.Type == nil || *runner.Type != "machine" {
		t.Errorf("Expected runner.Type to be 'machine', got %v", runner.Type)
	}
}

