package github

import (
	"github.com/aquasecurity/pipeline-parser/pkg/models"

	githubModels "github.com/aquasecurity/pipeline-parser/pkg/loaders/github/models"
)

func parseRunsOnToRunner(runsOn *githubModels.RunsOn) *models.Runner {
	if runsOn == nil {
		return nil
	}

	runner := &models.Runner{
		OS:            runsOn.OS,
		Arch:          runsOn.Arch,
		Labels:        &runsOn.Tags,
		SelfHosted:    &runsOn.SelfHosted,
		FileReference: runsOn.FileReference,
	}
	return runner
}
