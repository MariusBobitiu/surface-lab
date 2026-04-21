package headers

import (
	"context"

	headersv1 "github.com/MariusBobitiu/surface-lab/scanner-service/tools/headers/v1"
	"github.com/MariusBobitiu/surface-lab/scanner-service/models"
)

func Check(ctx context.Context, target string) models.ToolResult {
	return headersv1.Check(ctx, target)
}
