package circleci

import (
	"strings"

	circleciModels "github.com/aquasecurity/pipeline-parser/pkg/loaders/circleci/models"
	"github.com/aquasecurity/pipeline-parser/pkg/models"
	"github.com/aquasecurity/pipeline-parser/pkg/utils"
)

func parseJobSteps(steps []*circleciModels.Step) []*models.Step {
	if len(steps) == 0 {
		return nil
	}

	parsedSteps := []*models.Step{}

	for _, step := range steps {
		if step == nil {
			continue
		}

		parsedStep := parseStep(step)
		if parsedStep != nil {
			parsedSteps = append(parsedSteps, parsedStep)
		}
	}

	return parsedSteps
}

func parseStep(step *circleciModels.Step) *models.Step {
	if step == nil {
		return nil
	}

	parsedStep := &models.Step{
		FileReference: step.FileReference,
	}

	// Step can be a string (command/orb reference) or a map
	// We need to check the raw YAML to determine the type
	stepData := step.GetStep()

	// Try to parse as string first (simple command or orb reference)
	if stepStr, ok := stepData.(string); ok {
		return parseStringStep(stepStr, step.FileReference)
	}

	// Parse as map (structured step)
	if stepMap, ok := stepData.(map[string]interface{}); ok {
		return parseMapStep(stepMap, step.FileReference)
	}

	return parsedStep
}

func parseStringStep(stepStr string, fileRef *models.FileReference) *models.Step {
	step := &models.Step{
		FileReference: fileRef,
	}

	// Check for special CircleCI built-in steps
	switch stepStr {
	case "checkout":
		step.Name = utils.GetPtr("checkout")
		step.Type = models.TaskStepType
		// Checkout is a built-in step, we can represent it as a task
		step.Task = &models.Task{
			Name:        utils.GetPtr("checkout"),
			Type:        models.CITaskType,
			VersionType: models.None,
		}
		return step
	case "setup_remote_docker":
		step.Name = utils.GetPtr("setup_remote_docker")
		step.Type = models.TaskStepType
		step.Task = &models.Task{
			Name:        utils.GetPtr("setup_remote_docker"),
			Type:        models.CITaskType,
			VersionType: models.None,
		}
		return step
	}

	// Check if it's an orb reference (format: orb-name/command-name or orb-name/command-name@version)
	if strings.Contains(stepStr, "/") {
		parts := strings.Split(stepStr, "/")
		if len(parts) >= 2 {
			commandParts := strings.Split(parts[1], "@")
			commandName := commandParts[0]
			version := ""
			if len(commandParts) > 1 {
				version = commandParts[1]
			}

			step.Name = &commandName
			step.Type = models.TaskStepType
			step.Task = &models.Task{
				Name:        &stepStr, // Full orb reference
				Type:        models.CITaskType,
				Version:     &version,
				VersionType: detectVersionType(version),
			}
			return step
		}
	}

	// Default: treat as shell command
	step.Name = &stepStr
	step.Type = models.ShellStepType
	step.Shell = &models.Shell{
		Script: &stepStr,
	}
	return step
}

func parseMapStep(stepMap map[string]interface{}, fileRef *models.FileReference) *models.Step {
	step := &models.Step{
		FileReference: fileRef,
	}

	// Parse run step
	if runData, ok := stepMap["run"]; ok {
		return parseRunStep(runData, fileRef)
	}

	// Parse checkout step
	if _, ok := stepMap["checkout"]; ok {
		step.Name = utils.GetPtr("checkout")
		step.Type = models.TaskStepType
		step.Task = &models.Task{
			Name:        utils.GetPtr("checkout"),
			Type:        models.CITaskType,
			VersionType: models.None,
		}
		return step
	}

	// Parse other step types (save_cache, restore_cache, etc.)
	// These are typically utility steps that don't execute code
	for key := range stepMap {
		step.Name = &key
		step.Type = models.TaskStepType
		step.Task = &models.Task{
			Name:        &key,
			Type:        models.CITaskType,
			VersionType: models.None,
		}
		break
	}

	return step
}

func parseRunStep(runData interface{}, fileRef *models.FileReference) *models.Step {
	step := &models.Step{
		Type:          models.ShellStepType,
		FileReference: fileRef,
	}

	// If run is a string, it's just the command
	if runStr, ok := runData.(string); ok {
		step.Shell = &models.Shell{
			Script:        &runStr,
			FileReference: fileRef,
		}
		return step
	}

	// If run is a map, parse the configuration
	if runMap, ok := runData.(map[string]interface{}); ok {
		runStep := &circleciModels.RunStepConfig{}
		
		// Convert map to RunStepConfig
		if command, ok := runMap["command"].(string); ok {
			runStep.Command = command
		}
		if name, ok := runMap["name"].(string); ok {
			runStep.Name = name
			step.Name = &name
		}
		if shell, ok := runMap["shell"]; ok {
			runStep.Shell = shell
		}
		if env, ok := runMap["environment"]; ok {
			runStep.Environment = env
		}
		if workingDir, ok := runMap["working_directory"].(string); ok {
			runStep.WorkingDirectory = workingDir
			step.WorkingDirectory = &workingDir
		}
		if when, ok := runMap["when"].(string); ok {
			// Parse when condition
			if when == "on_fail" {
				step.FailsPipeline = utils.GetPtr(false)
			}
		}

		// Parse command
		if runStep.Command != "" {
			step.Shell = &models.Shell{
				Script:        &runStep.Command,
				FileReference: fileRef,
			}
		}

		// Parse shell type
		if runStep.Shell != nil {
			if shellStr, ok := runStep.Shell.(string); ok {
				step.Shell.Type = &shellStr
			}
		}

		// Parse environment variables
		if runStep.Environment != nil {
			step.EnvironmentVariables = parseEnvironmentVariables(runStep.Environment)
		}
	}

	return step
}

func detectVersionType(version string) models.VersionType {
	if version == "" {
		return models.None
	}
	if strings.HasPrefix(version, "v") {
		return models.TagVersion
	}
	if strings.Contains(version, "/") {
		return models.BranchVersion
	}
	return models.Latest
}

