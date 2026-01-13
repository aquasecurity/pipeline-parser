package circleci

import (
	circleciModels "github.com/aquasecurity/pipeline-parser/pkg/loaders/circleci/models"
	"github.com/aquasecurity/pipeline-parser/pkg/models"
)

type CircleCIParser struct{}

func (c *CircleCIParser) Parse(config *circleciModels.Config) (*models.Pipeline, error) {
	pipeline := &models.Pipeline{}

	// Parse workflows (triggers)
	if config.Workflows != nil && len(config.Workflows) > 0 {
		pipeline.Triggers = parseWorkflows(config.Workflows)
	}

	// Parse jobs
	if config.Jobs != nil {
		var err error
		if pipeline.Jobs, err = parseJobs(config.Jobs); err != nil {
			return nil, err
		}
	}

	// Parse defaults (environment variables from parameters)
	if config.Parameters != nil {
		pipeline.Defaults = parseDefaults(config.Parameters)
	}

	return pipeline, nil
}

