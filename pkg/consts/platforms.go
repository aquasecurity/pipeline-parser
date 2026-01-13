package consts

import "github.com/aquasecurity/pipeline-parser/pkg/models"

const (
	GitHubPlatform    models.Platform = "github"
	GitLabPlatform    models.Platform = "gitlab"
	AzurePlatform     models.Platform = "azure"
	BitbucketPlatform models.Platform = "bitbucket"
	CircleCIPlatform  models.Platform = "circleci"
)

var Platforms = []models.Platform{
	GitHubPlatform,
	GitLabPlatform,
	AzurePlatform,
	BitbucketPlatform,
	CircleCIPlatform,
}
