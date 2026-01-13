package circleci

import (
	"strings"

	circleciModels "github.com/aquasecurity/pipeline-parser/pkg/loaders/circleci/models"
	"github.com/aquasecurity/pipeline-parser/pkg/models"
)

func parseEnvironmentVariables(env interface{}) *models.EnvironmentVariablesRef {
	if env == nil {
		return nil
	}

	envVars := models.EnvironmentVariables{}

	// Handle map[string]interface{}
	if envMap, ok := env.(map[string]interface{}); ok {
		for k, v := range envMap {
			if v != nil {
				envVars[k] = v
			}
		}
	}

	// Handle []string (KEY=VALUE format)
	if envArray, ok := env.([]interface{}); ok {
		for _, item := range envArray {
			if envStr, ok := item.(string); ok {
				parts := strings.SplitN(envStr, "=", 2)
				if len(parts) == 2 {
					envVars[parts[0]] = parts[1]
				}
			}
		}
	}

	// Handle string (single environment variable)
	if envStr, ok := env.(string); ok {
		// This is less common but possible
		envVars[""] = envStr
	}

	if len(envVars) == 0 {
		return nil
	}

	return &models.EnvironmentVariablesRef{
		EnvironmentVariables: envVars,
	}
}

func parseDefaults(parameters *circleciModels.Parameters) *models.Defaults {
	if parameters == nil || parameters.Parameters == nil {
		return nil
	}

	defaults := &models.Defaults{}

	// Convert parameters to environment variables if they have defaults
	envVars := models.EnvironmentVariables{}
	for name, param := range parameters.Parameters {
		if param != nil && param.Default != nil {
			envVars[name] = param.Default
		}
	}

	if len(envVars) > 0 {
		defaults.EnvironmentVariables = &models.EnvironmentVariablesRef{
			EnvironmentVariables: envVars,
		}
	}

	return defaults
}

