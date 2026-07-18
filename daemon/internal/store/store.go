package store

import (
	"database/sql"
	"fmt"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"

	"naust/daemon/internal/store/ent"

	_ "github.com/jackc/pgx/v5/stdlib" // database/sql driver: pgx
	_ "modernc.org/sqlite"             // database/sql driver: sqlite (CGO-free)
)

// Engine selects the database backend. Adding an engine means adding a
// case in Open plus a test-matrix entry - nothing above this file changes.
type Engine string

const (
	EngineSQLite   Engine = "sqlite"
	EnginePostgres Engine = "postgres"
)

// Open connects to the control-plane database and returns the typed
// client. For SQLite, dsn is a plain file path; the pragmas the engine
// needs (WAL, busy_timeout, foreign keys) are appended here so callers
// never carry engine detail. For Postgres, dsn is a standard connection
// string or URL.
//
// Callers own migration: run client.Schema.Create(ctx) once at startup.
func Open(engine Engine, dsn string) (*ent.Client, error) {
	switch engine {
	case EngineSQLite:
		db, err := sql.Open("sqlite", sqliteDSN(dsn))
		if err != nil {
			return nil, fmt.Errorf("open sqlite: %w", err)
		}
		// A single connection serializes all access: no SQLITE_BUSY
		// surprises, writers never contend. Control-plane query volume
		// makes this a non-cost; revisit only with profiler evidence.
		db.SetMaxOpenConns(1)
		return ent.NewClient(ent.Driver(entsql.OpenDB(dialect.SQLite, db))), nil
	case EnginePostgres:
		db, err := sql.Open("pgx", dsn)
		if err != nil {
			return nil, fmt.Errorf("open postgres: %w", err)
		}
		return ent.NewClient(ent.Driver(entsql.OpenDB(dialect.Postgres, db))), nil
	default:
		return nil, fmt.Errorf("unknown database engine %q", engine)
	}
}

func sqliteDSN(path string) string {
	return "file:" + path +
		"?_pragma=busy_timeout(10000)" +
		"&_pragma=journal_mode(WAL)" +
		"&_pragma=foreign_keys(1)"
}
