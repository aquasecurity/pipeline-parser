package handler

import (
	"github.com/aquasecurity/pipeline-parser/pkg/consts"
	"github.com/aquasecurity/pipeline-parser/pkg/enhancers"
	bitbucketEnhancer "github.com/aquasecurity/pipeline-parser/pkg/enhancers/bitbucket"
	"github.com/aquasecurity/pipeline-parser/pkg/loaders"
	bitbucketLoader "github.com/aquasecurity/pipeline-parser/pkg/loaders/bitbucket"
	bitbucketModels "github.com/aquasecurity/pipeline-parser/pkg/loaders/bitbucket/models"
	"github.com/aquasecurity/pipeline-parser/pkg/models"
	"github.com/aquasecurity/pipeline-parser/pkg/parsers"
	bitbucketParser "github.com/aquasecurity/pipeline-parser/pkg/parsers/bitbucket"
)

type BitbucketHandler struct{}

func (g *BitbucketHandler) GetPlatform() models.Platform {
	return consts.BitbucketPlatform
}

func (g *BitbucketHandler) GetLoader() loaders.Loader[bitbucketModels.Pipeline] {
	return &bitbucketLoader.BitbucketLoader{}
}

func (g *BitbucketHandler) GetParser() parsers.Parser[bitbucketModels.Pipeline] {
	return &bitbucketParser.BitbucketParser{}
}

func (g *BitbucketHandler) GetEnhancer() enhancers.Enhancer {
	return &bitbucketEnhancer.BitbucketEnhancer{}
}
