package github

import (
	githubModels "github.com/aquasecurity/pipeline-parser/pkg/loaders/github/models"
	"github.com/aquasecurity/pipeline-parser/pkg/models"
)

func parseEnvironmentVariablesRef(envRef *githubModels.EnvironmentVariablesRef) *models.EnvironmentVariablesRef {
	if envRef == nil {
		return nil
	}

	return &models.EnvironmentVariablesRef{
		EnvironmentVariables: envRef.EnvironmentVariables,
		FileReference:        envRef.FileReference,
	}
}
