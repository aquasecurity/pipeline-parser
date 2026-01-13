package circleci

import (
	circleciModels "github.com/aquasecurity/pipeline-parser/pkg/loaders/circleci/models"
	"github.com/aquasecurity/pipeline-parser/pkg/models"
)

func parseWorkflows(workflows map[string]*circleciModels.Workflow) *models.Triggers {
	if len(workflows) == 0 {
		return nil
	}

	triggers := []*models.Trigger{}

	for _, workflow := range workflows {
		if workflow == nil {
			continue
		}

		// Parse scheduled triggers
		if workflow.Triggers != nil && workflow.Triggers.Schedule != nil {
			schedule := workflow.Triggers.Schedule
			trigger := &models.Trigger{
				Event: models.ScheduledEvent,
			}

			if schedule.Cron != "" {
				schedules := []string{schedule.Cron}
				trigger.Schedules = &schedules
			}

			if schedule.Filters != nil {
				if schedule.Filters.Branches != nil {
					trigger.Branches = &models.Filter{
						AllowList: schedule.Filters.Branches.Only,
						DenyList:  schedule.Filters.Branches.Ignore,
					}
				}
				if schedule.Filters.Tags != nil {
					trigger.Tags = &models.Filter{
						AllowList: schedule.Filters.Tags.Only,
						DenyList:  schedule.Filters.Tags.Ignore,
					}
				}
			}

			trigger.FileReference = workflow.FileReference
			triggers = append(triggers, trigger)
		}

		// If no explicit triggers, workflows are typically triggered on push
		// CircleCI workflows without triggers run on every push
		if workflow.Triggers == nil || workflow.Triggers.Schedule == nil {
			trigger := &models.Trigger{
				Event:         models.PushEvent,
				FileReference: workflow.FileReference,
			}
			triggers = append(triggers, trigger)
		}
	}

	if len(triggers) == 0 {
		return nil
	}

	return &models.Triggers{
		Triggers: triggers,
	}
}
