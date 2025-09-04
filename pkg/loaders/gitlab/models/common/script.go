package common

import (
	"github.com/aquasecurity/pipeline-parser/pkg/consts"
	"github.com/aquasecurity/pipeline-parser/pkg/loaders/utils"
	"github.com/aquasecurity/pipeline-parser/pkg/models"
	"gopkg.in/yaml.v3"
)

type Script struct {
	Commands      []string
	FileReference *models.FileReference
}

func (s *Script) UnmarshalYAML(node *yaml.Node) error {
	s.FileReference = utils.GetFileReference(node)

	if node.Tag == consts.StringTag {
		s.Commands = []string{node.Value}
		s.FileReference.EndRef.Column += len("script: ")
		return nil
	}

	if node.Tag == consts.SequenceTag {
		commands, err := utils.ParseYamlStringSequenceToSlice(node, "Script")
		if err != nil {
			return err
		}
		s.Commands = commands
		return nil
	}

	return consts.NewErrInvalidYamlTag(node.Tag, "Script")
}
