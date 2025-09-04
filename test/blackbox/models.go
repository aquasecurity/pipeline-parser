package blackbox

import "github.com/aquasecurity/pipeline-parser/pkg/models"

type TestCase struct {
	Filename    string
	TestdataDir string
	Expected    *models.Pipeline
	ShouldFail  bool
}
