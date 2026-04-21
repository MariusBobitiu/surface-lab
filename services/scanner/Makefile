GO ?= go
SQLC ?= sqlc
MIGRATE ?= migrate
DATABASE_URL ?=
MIGRATIONS_DIR ?= db/migrations
MIGRATIONS_TABLE ?= %22meta%22.%22schema_migrations%22
MIGRATIONS_TABLE_QUOTED ?= true

-include .env
-include ../../.env

export DATABASE_URL

.PHONY: db-migrate-up db-migrate-down sqlc-generate run test

db-migrate-up:
	@test -n "$(DATABASE_URL)" || (echo "DATABASE_URL is not set" && exit 1)
	$(MIGRATE) -path $(MIGRATIONS_DIR) -database "$(DATABASE_URL)&x-migrations-table=$(MIGRATIONS_TABLE)&x-migrations-table-quoted=$(MIGRATIONS_TABLE_QUOTED)" up

db-migrate-down:
	@test -n "$(DATABASE_URL)" || (echo "DATABASE_URL is not set" && exit 1)
	$(MIGRATE) -path $(MIGRATIONS_DIR) -database "$(DATABASE_URL)&x-migrations-table=$(MIGRATIONS_TABLE)&x-migrations-table-quoted=$(MIGRATIONS_TABLE_QUOTED)" down 1

sqlc-generate:
	$(SQLC) generate

run:
	$(GO) run .

test:
	$(GO) test ./...
