package circleci

import (
	"github.com/aquasecurity/pipeline-parser/pkg/enhancers"
	"github.com/aquasecurity/pipeline-parser/pkg/models"
)

type CircleCIEnhancer struct{}

func (c *CircleCIEnhancer) LoadImportedPipelines(data *models.Pipeline, credentials *models.Credentials, _, baseUrl *string) ([]*enhancers.ImportedPipeline, error) {
	// CircleCI uses orbs which are typically resolved at runtime
	// For now, we don't load imported pipelines/orbs
	// This could be enhanced in the future to fetch orb definitions
	return []*enhancers.ImportedPipeline{}, nil
}

func (c *CircleCIEnhancer) Enhance(data *models.Pipeline, importedPipelines []*enhancers.ImportedPipeline) (*models.Pipeline, error) {
	// For now, no enhancement needed
	// Could be enhanced to merge orb definitions in the future
	return data, nil
}

func (c *CircleCIEnhancer) InheritParentPipelineData(parent, child *models.Pipeline) *models.Pipeline {
	// CircleCI doesn't have a parent/child pipeline concept like GitLab includes
	return child
}

