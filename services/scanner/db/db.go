package db

import (
	"context"
	"fmt"

	generateddb "github.com/MariusBobitiu/surface-lab/scanner-service/db/generated"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Client keeps the connection pool and generated queries together for callers.
type Client struct {
	Pool    *pgxpool.Pool
	Queries *generateddb.Queries
}

func Open(ctx context.Context, databaseURL string) (*Client, error) {
	if databaseURL == "" {
		return nil, fmt.Errorf("database url is required")
	}

	cfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse database url: %w", err)
	}

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("open database pool: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}

	return &Client{
		Pool:    pool,
		Queries: generateddb.New(pool),
	}, nil
}

func NewQueries(conn generateddb.DBTX) *generateddb.Queries {
	return generateddb.New(conn)
}

func (c *Client) Close() {
	if c == nil || c.Pool == nil {
		return
	}

	c.Pool.Close()
}
