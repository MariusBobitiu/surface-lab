package files

import (
	"context"

	"github.com/MariusBobitiu/surface-lab/scanner-service/models"
	filesv1 "github.com/MariusBobitiu/surface-lab/scanner-service/tools/files/v1"
)

func Check(ctx context.Context, target string) models.ToolResult {
	return filesv1.Check(ctx, target)
}
