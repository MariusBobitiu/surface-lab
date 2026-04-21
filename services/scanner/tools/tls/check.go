package tls

import (
	"context"

	"github.com/MariusBobitiu/surface-lab/scanner-service/models"
	tlsv1 "github.com/MariusBobitiu/surface-lab/scanner-service/tools/tls/v1"
)

func Check(ctx context.Context, target string) models.ToolResult {
	return tlsv1.Check(ctx, target)
}
