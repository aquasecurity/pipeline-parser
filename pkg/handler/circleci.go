package handler

import (
	"github.com/aquasecurity/pipeline-parser/pkg/consts"
	"github.com/aquasecurity/pipeline-parser/pkg/enhancers"
	circleciEnhancer "github.com/aquasecurity/pipeline-parser/pkg/enhancers/circleci"
	"github.com/aquasecurity/pipeline-parser/pkg/loaders"
	circleciLoader "github.com/aquasecurity/pipeline-parser/pkg/loaders/circleci"
	circleciModels "github.com/aquasecurity/pipeline-parser/pkg/loaders/circleci/models"
	"github.com/aquasecurity/pipeline-parser/pkg/models"
	"github.com/aquasecurity/pipeline-parser/pkg/parsers"
	circleciParser "github.com/aquasecurity/pipeline-parser/pkg/parsers/circleci"
)

type CircleCIHandler struct{}

func (c *CircleCIHandler) GetPlatform() models.Platform {
	return consts.CircleCIPlatform
}

func (c *CircleCIHandler) GetLoader() loaders.Loader[circleciModels.Config] {
	return &circleciLoader.CircleCILoader{}
}

func (c *CircleCIHandler) GetParser() parsers.Parser[circleciModels.Config] {
	return &circleciParser.CircleCIParser{}
}

func (c *CircleCIHandler) GetEnhancer() enhancers.Enhancer {
	return &circleciEnhancer.CircleCIEnhancer{}
}

