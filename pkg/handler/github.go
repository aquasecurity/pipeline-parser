package handler

import (
	"github.com/aquasecurity/pipeline-parser/pkg/consts"
	"github.com/aquasecurity/pipeline-parser/pkg/enhancers"
	githubEnhancer "github.com/aquasecurity/pipeline-parser/pkg/enhancers/github"
	"github.com/aquasecurity/pipeline-parser/pkg/loaders"
	githubLoader "github.com/aquasecurity/pipeline-parser/pkg/loaders/github"
	githubModels "github.com/aquasecurity/pipeline-parser/pkg/loaders/github/models"
	"github.com/aquasecurity/pipeline-parser/pkg/models"
	"github.com/aquasecurity/pipeline-parser/pkg/parsers"
	githubParser "github.com/aquasecurity/pipeline-parser/pkg/parsers/github"
)

type GitHubHandler struct{}

func (g *GitHubHandler) GetPlatform() models.Platform {
	return consts.GitHubPlatform
}

func (g *GitHubHandler) GetLoader() loaders.Loader[githubModels.Workflow] {
	return &githubLoader.GitHubLoader{}
}

func (g *GitHubHandler) GetParser() parsers.Parser[githubModels.Workflow] {
	return &githubParser.GitHubParser{}
}

func (g *GitHubHandler) GetEnhancer() enhancers.Enhancer {
	return &githubEnhancer.GitHubEnhancer{}
}
