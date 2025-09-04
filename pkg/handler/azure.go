package handler

import (
	"github.com/aquasecurity/pipeline-parser/pkg/consts"
	"github.com/aquasecurity/pipeline-parser/pkg/enhancers"
	azureEnhancer "github.com/aquasecurity/pipeline-parser/pkg/enhancers/azure"
	"github.com/aquasecurity/pipeline-parser/pkg/loaders"
	azureLoader "github.com/aquasecurity/pipeline-parser/pkg/loaders/azure"
	azureModels "github.com/aquasecurity/pipeline-parser/pkg/loaders/azure/models"
	"github.com/aquasecurity/pipeline-parser/pkg/models"
	"github.com/aquasecurity/pipeline-parser/pkg/parsers"
	azureParser "github.com/aquasecurity/pipeline-parser/pkg/parsers/azure"
)

type AzureHandler struct{}

func (g *AzureHandler) GetPlatform() models.Platform {
	return consts.AzurePlatform
}

func (g *AzureHandler) GetLoader() loaders.Loader[azureModels.Pipeline] {
	return &azureLoader.AzureLoader{}
}

func (g *AzureHandler) GetParser() parsers.Parser[azureModels.Pipeline] {
	return &azureParser.AzureParser{}
}

func (g *AzureHandler) GetEnhancer() enhancers.Enhancer {
	return &azureEnhancer.AzureEnhancer{}
}
