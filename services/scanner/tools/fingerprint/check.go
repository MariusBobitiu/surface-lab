package fingerprint

import (
	"context"

	"github.com/MariusBobitiu/surface-lab/scanner-service/models"
	fingerprintv1 "github.com/MariusBobitiu/surface-lab/scanner-service/tools/fingerprint/v1"
)

func Check(ctx context.Context, target string) models.ToolResult {
	return fingerprintv1.Check(ctx, target)
}
