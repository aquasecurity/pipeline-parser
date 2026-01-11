package circleci

import (
	circleciModels "github.com/aquasecurity/pipeline-parser/pkg/loaders/circleci/models"
	"github.com/aquasecurity/pipeline-parser/pkg/models"
	"github.com/aquasecurity/pipeline-parser/pkg/utils"
)

func parseJobs(jobs map[string]*circleciModels.Job) ([]*models.Job, error) {
	if len(jobs) == 0 {
		return nil, nil
	}

	parsedJobs := []*models.Job{}

	for jobName, job := range jobs {
		if job == nil {
			continue
		}

		// Skip non-build jobs (approval, release, lock, unlock, no-op)
		if job.Type != "" && job.Type != "build" {
			continue
		}

		// Create a copy of jobName to avoid pointer sharing issues in loops
		jobID := jobName
		jobNameCopy := jobName
		
		parsedJob := &models.Job{
			ID:            &jobID,
			Name:          &jobNameCopy,
			FileReference: job.FileReference,
		}

		// Parse description
		if job.Description != "" {
			parsedJob.Name = &job.Description
		}

		// Parse steps
		if job.Steps != nil {
			parsedJob.Steps = parseJobSteps(job.Steps)
		}

		// Parse environment variables
		if job.Environment != nil {
			parsedJob.EnvironmentVariables = parseEnvironmentVariables(job.Environment)
		}

		// Parse runner (executor)
		parsedJob.Runner = parseJobRunner(job)

		// Parse working directory
		if job.WorkingDirectory != "" {
			// Steps will inherit this, but we can also set it at job level if needed
		}

		// Parse dependencies from workflow (will be handled in workflow parsing)
		// For now, we'll leave dependencies empty as they're defined in workflows

		parsedJobs = append(parsedJobs, parsedJob)
	}

	return parsedJobs, nil
}

func parseJobRunner(job *circleciModels.Job) *models.Runner {
	runner := &models.Runner{}

	// Parse Docker executor
	if job.Docker != nil && len(job.Docker) > 0 {
		docker := job.Docker[0] // Use first docker image
		runner.Type = utils.GetPtr("docker")
		runner.DockerMetadata = &models.DockerMetadata{
			Image: &docker.Image,
		}
		if docker.Auth != nil {
			// Store auth info if needed
		}
		return runner
	}

	// Parse Machine executor
	if job.Machine != nil {
		runner.Type = utils.GetPtr("machine")
		if job.Machine.Image != "" {
			runner.DockerMetadata = &models.DockerMetadata{
				Image: &job.Machine.Image,
			}
		}
		if job.Machine.ResourceClass != "" {
			runner.Labels = &[]string{job.Machine.ResourceClass}
		}
		return runner
	}

	// Parse macOS executor
	if job.MacOS != nil {
		runner.Type = utils.GetPtr("macos")
		runner.OS = utils.GetPtr("macos")
		if job.MacOS.ResourceClass != "" {
			runner.Labels = &[]string{job.MacOS.ResourceClass}
		}
		return runner
	}

	// Parse resource class (generic)
	if job.ResourceClass != "" {
		runner.Labels = &[]string{job.ResourceClass}
	}

	return runner
}

