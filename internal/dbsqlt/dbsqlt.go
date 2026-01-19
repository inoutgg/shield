package dbsqlt

import (
	"os"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.segfaultmedaddy.com/pgxephemeraltest"
)

var (
	mu          sync.RWMutex                  //nolint:gochecknoglobals
	poolFactory *pgxephemeraltest.PoolFactory //nolint:gochecknoglobals
)

// Pool returns a pgxpool.Pool connected to ephemeral database.
//
// It lazily creates a pool factory connected to the database located at
// the given URL (TEST_DATABASE_URL env var).
func Pool(tb testing.TB) *pgxpool.Pool {
	tb.Helper()

	try := func() *pgxephemeraltest.PoolFactory {
		mu.RLock()
		defer mu.RUnlock()

		return poolFactory
	}

	get := func() *pgxephemeraltest.PoolFactory {
		// First check if the pool manager is already initialized...
		if db := try(); db != nil {
			return db
		}

		mu.Lock()
		defer mu.Unlock()

		var err error

		// ...otherwise create a new one connected to TEST_DATABASE_URL instance...
		poolFactory, err = pgxephemeraltest.NewPoolFactoryFromConnString(
			tb.Context(),
			os.Getenv("TEST_DATABASE_URL"),
			m,
		)
		if err != nil {
			tb.Fatal(err)
		}

		return poolFactory
	}

	// Finally return a new pool created from the pool factory.
	return get().Pool(tb)
}
