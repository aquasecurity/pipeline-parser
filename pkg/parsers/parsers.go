package parsers

import "github.com/aquasecurity/pipeline-parser/pkg/models"

type Parser[T any] interface {
	Parse(*T) (*models.Pipeline, error)
}
