package blackbox

import (
	"testing"

	"github.com/aquasecurity/pipeline-parser/pkg/consts"
	"github.com/aquasecurity/pipeline-parser/pkg/models"
	"github.com/aquasecurity/pipeline-parser/pkg/testutils"
	"github.com/aquasecurity/pipeline-parser/pkg/utils"
)

func TestCircleCI(t *testing.T) {
	testCases := []TestCase{
		{
			Filename: "build-and-scan.yaml",
			Expected: SortPipeline(&models.Pipeline{
				Platform: consts.CircleCIPlatform,
				Triggers: &models.Triggers{
					Triggers: []*models.Trigger{
						{
							Event: models.PushEvent,
						},
					},
				},
				Jobs: []*models.Job{
					{
						ID:   utils.GetPtr("BILLY"),
						Name: utils.GetPtr("BILLY"),
						Runner: &models.Runner{
							Type: utils.GetPtr("docker"),
							DockerMetadata: &models.DockerMetadata{
								Image: utils.GetPtr("cimg/base:current"),
							},
						},
						Metadata: models.Metadata{
							Build: true,
						},
						Steps: []*models.Step{
							{
								Name: utils.GetPtr("checkout"),
								Type: models.TaskStepType,
								Task: &models.Task{
									Name:        utils.GetPtr("checkout"),
									Type:        models.CITaskType,
									VersionType: models.None,
								},
								FileReference: testutils.CreateFileReference(32, 9, 32, 17),
							},
							{
								Name: utils.GetPtr("setup_remote_docker"),
								Type: models.TaskStepType,
								Task: &models.Task{
									Name:        utils.GetPtr("setup_remote_docker"),
									Type:        models.CITaskType,
									VersionType: models.None,
								},
								FileReference: testutils.CreateFileReference(33, 9, 33, 28),
							},
							{
								Name: utils.GetPtr("Build docker image"),
								Type: models.ShellStepType,
								Shell: &models.Shell{
									Script:        utils.GetPtr("docker build -t aquasupportemea/insecure-bank-app:${CIRCLE_SHA1} ."),
									FileReference: testutils.CreateFileReference(34, 9, 36, 86),
								},
								Metadata: models.Metadata{
									Build: true,
								},
								FileReference: testutils.CreateFileReference(34, 9, 36, 86),
							},
							{
								Name: utils.GetPtr("SBOM Generation - Manifest Generation"),
								Type: models.ShellStepType,
								Shell: &models.Shell{
									Script: utils.GetPtr(`export CIRCLE_REPOSITORY_URL=https://github.com/aquasupportemea/insecure-banker-andreas-eu_circleci.git
export BILLY_SERVER=https://billy.eu-1.codesec.aquasec.com
curl -sLo install.sh download.codesec.aquasec.com/billy/install.sh
curl -sLo install.sh.checksum https://github.com/argonsecurity/releases/releases/latest/download/install.sh.checksum
if ! cat install.sh.checksum | sha256sum --check; then
  echo "install.sh checksum failed"
  exit 1
fi
BINDIR="." sh install.sh
rm install.sh install.sh.checksum
./billy generate \
  --access-token "${GITHUB_TOKEN}" \
  --aqua-key "${AQUA_KEY}" \
  --aqua-secret "${AQUA_SECRET}" \
  --cspm-url https://eu-1.api.cloudsploit.com \
  --artifact-path "aquasupportemea/insecure-bank-app:${CIRCLE_SHA1}"
`),
									FileReference: testutils.CreateFileReference(37, 9, 55, 20),
								},
								FileReference: testutils.CreateFileReference(37, 9, 55, 20),
							},
						},
					},
					{
						ID:   utils.GetPtr("TRIVY"),
						Name: utils.GetPtr("TRIVY"),
						Runner: &models.Runner{
							Type: utils.GetPtr("docker"),
							DockerMetadata: &models.DockerMetadata{
								Image: utils.GetPtr("aquasec/aqua-scanner"),
							},
						},
						Steps: []*models.Step{
							{
								Name: utils.GetPtr("checkout"),
								Type: models.TaskStepType,
								Task: &models.Task{
									Name:        utils.GetPtr("checkout"),
									Type:        models.CITaskType,
									VersionType: models.None,
								},
								FileReference: testutils.CreateFileReference(13, 9, 13, 17),
							},
							{
								Name: utils.GetPtr("Aqua code scanning (SCA, IaC, SAST)"),
								Type: models.ShellStepType,
								Shell: &models.Shell{
									Script: utils.GetPtr(`export CIRCLE_REPOSITORY_URL=https://github.com/aquasupportemea/insecure-banker-andreas-eu_circleci.git
export AQUA_URL=https://api.eu-1.supply-chain.cloud.aquasec.com
export CSPM_URL=https://eu-1.api.cloudsploit.com
export TRIVY_RUN_AS_PLUGIN=aqua
export ENABLE_TRIVY_STDOUT='true'
export TRIVY_USERNAME="${TRIVY_USERNAME}"
export TRIVY_PASSWORD="${TRIVY_PASSWORD}"
export GITHUB_TOKEN="${GITHUB_TOKEN}"

trivy fs --sast --reachability --scanners misconfig,vuln,secret --db-repository=registry.aquasec.com/trivy-db:2 --checks-bundle-repository=registry.aquasec.com/trivy-checks:1 --java-db-repository=registry.aquasec.com/trivy-java-db:1 .
`),
									FileReference: testutils.CreateFileReference(14, 9, 26, 20),
								},
								FileReference: testutils.CreateFileReference(14, 9, 26, 20),
							},
						},
					},
				},
			}),
		},
	}
	executeTestCases(t, testCases, "circleci", consts.CircleCIPlatform, "", "")
}
