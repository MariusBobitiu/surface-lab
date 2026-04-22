package execute

import (
	"context"
	"time"

	"github.com/MariusBobitiu/surface-lab/service-baseline/models"
)

func Run(ctx context.Context, target string, input map[string]interface{}) models.RunStackResult {
	startedAt := time.Now()

	select {
	case <-ctx.Done():
		return models.RunStackResult{
			Service:    "service-baseline",
			Target:     target,
			Status:     "timeout",
			DurationMS: time.Since(startedAt).Milliseconds(),
			Metadata: map[string]interface{}{
				"placeholder": true,
			},
			Error: ctx.Err().Error(),
		}
	default:
	}

	return models.RunStackResult{
		Service:    "service-baseline",
		Target:     target,
		Status:     "completed",
		DurationMS: time.Since(startedAt).Milliseconds(),
		Findings: []models.Finding{
			{
				Type:       "informational",
				Category:   "baseline_service",
				Title:      "Placeholder stack execution completed",
				Severity:   "info",
				Confidence: "high",
				Evidence:   "service-baseline placeholder handler executed successfully",
				Details: map[string]interface{}{
					"placeholder": true,
				},
			},
		},
		Metadata: map[string]interface{}{
			"placeholder": true,
			"input":       input,
		},
	}
}
