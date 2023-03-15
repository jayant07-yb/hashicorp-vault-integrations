package ysql

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/vault/sdk/physical"

	log "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-uuid"

	"github.com/armon/go-metrics"
	"github.com/lib/pq"
)

const (

	// The lock TTL matches the default that Consul API uses, 15 seconds.
	// Used as part of SQL commands to set/extend lock expiry time relative to
	// database clock.
	YSQLLockTTLSeconds = 15

	// The amount of time to wait between the lock renewals
	YSQLLockRenewInterval = 5 * time.Second

	// YSQLLockRetryInterval is the amount of time to wait
	// if a lock fails before trying again.
	YSQLLockRetryInterval = time.Second
)

// Verify YSQLBackend satisfies the correct interfaces
var _ physical.Backend = (*YSQLBackend)(nil)

//
// HA backend was implemented based on the DynamoDB backend pattern
// With distinction using central ysql clock, hereby avoiding
// possible issues with multiple clocks
//
var (
	_ physical.HABackend = (*YSQLBackend)(nil)
	_ physical.Lock      = (*YSQLLock)(nil)
)

// YSQL Backend is a physical backend that stores data
// within a YSQL database.
type YSQLBackend struct {
	table        string
	client       *sql.DB
	putQuery    string
	getQuery    string
	deleteQuery string
	listQuery   string

	ha_table                 string
	haGetLockValueQuery      string
	haUpsertLockIdentityExec string
	haDeleteLockExec         string

	haEnabled  bool
	logger     log.Logger
	permitPool *physical.PermitPool
}

// YSQLLock implements a lock using an YSQL client.
type YSQLLock struct {
	backend    *YSQLBackend
	value, key string
	identity   string
	lock       sync.Mutex

	renewTicker *time.Ticker

	// ttlSeconds is how long a lock is valid for
	ttlSeconds int

	// renewInterval is how much time to wait between lock renewals.  must be << ttl
	renewInterval time.Duration

	// retryInterval is how much time to wait between attempts to grab the lock
	retryInterval time.Duration
}

// NewYSQLBackend constructs a YSQL backend using the given
// API client, server address, credentials, and database.
func NewYSQLBackend(conf map[string]string, logger log.Logger) (physical.Backend, error) {
	// Get the YSQL credentials to perform read/write operations.
	connURL := connectionURL(conf)
	if connURL == "" {
		return nil, fmt.Errorf("missing connection_url")
	}

	unquotedTable, ok := conf["table"]
	if !ok {
		unquotedTable = "vault_kv_store"
	}
	quotedTable := pq.QuoteIdentifier(unquotedTable)

	maxParStr, ok := conf["max_parallel"]
	var maxParInt int
	var err error
	if ok {
		maxParInt, err = strconv.Atoi(maxParStr)
		if err != nil {
			return nil, fmt.Errorf("failed parsing max_parallel parameter: %w", err)
		}
		if logger.IsDebug() {
			logger.Debug("max_parallel set", "max_parallel", maxParInt)
		}
	} else {
		maxParInt = physical.DefaultParallelOperations
	}

	maxIdleConnsStr, maxIdleConnsIsSet := conf["max_idle_connections"]
	var maxIdleConns int
	if maxIdleConnsIsSet {
		maxIdleConns, err = strconv.Atoi(maxIdleConnsStr)
		if err != nil {
			return nil, fmt.Errorf("failed parsing max_idle_connections parameter: %w", err)
		}
		if logger.IsDebug() {
			logger.Debug("max_idle_connections set", "max_idle_connections", maxIdleConnsStr)
		}
	}

	// Create YSQL handle for the database.
	db, err := sql.Open("postgres", connURL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to yugabytedb-ysql: %w", err)
	}
	db.SetMaxOpenConns(maxParInt)

	if maxIdleConnsIsSet {
		db.SetMaxIdleConns(maxIdleConns)
	}

	unquotedHaTable, ok := conf["ha_table"]
	if !ok {
		unquotedHaTable = "vault_ha_locks"
	}
	quotedHaTable := pq.QuoteIdentifier(unquotedHaTable)

	//Ysql supports upsert

	var putQuery string = fmt.Sprintf(`INSERT INTO %s VALUES($1, $2, $3, $4)
							ON CONFLICT (path, key) DO
							UPDATE SET (parent_path, path, key, value) = ($1, $2, $3, $4)`,
							quotedTable)

	var getQuery string = fmt.Sprintf("SELECT value FROM %s WHERE path = $1 AND key = $2",
							quotedTable)

	var deleteQuery string = fmt.Sprintf("DELETE FROM %s WHERE path = $1 AND key = $2",
							quotedTable)

	var listQuery string = fmt.Sprintf(`SELECT key FROM %s WHERE path = $1
							UNION ALL SELECT DISTINCT substring(substr(path, length($1)+1) from '^.*?/') FROM %s
							WHERE parent_path LIKE $1 || '%%'`,
		quotedTable, quotedTable)

	var haGetLockValueQuery string = fmt.Sprintf(" SELECT ha_value FROM %s WHERE NOW() <= valid_until AND ha_key = $1 ",quotedHaTable)

	var	haUpsertLockIdentityExec string = fmt.Sprintf(` INSERT INTO %s as t (ha_identity, ha_key, ha_value, valid_until) VALUES ($1, $2, $3, NOW() + $4 * INTERVAL '1 seconds'  )
							ON CONFLICT (ha_key) DO
							UPDATE SET (ha_identity, ha_key, ha_value, valid_until) = ($1, $2, $3, NOW() + $4 * INTERVAL '1 seconds')
							WHERE (t.valid_until < NOW() AND t.ha_key = $2) OR
							(t.ha_identity = $1 AND t.ha_key = $2) `,quotedHaTable)

	var haDeleteLockExec string = fmt.Sprintf("DELETE FROM %s WHERE ha_identity=$1 AND ha_key=$2 ",quotedHaTable )

	// Setup the backend.
	m := &YSQLBackend{
		table:      	quotedTable,
		client:     	db,
		putQuery:   	putQuery,
		getQuery:		getQuery,
		deleteQuery:	deleteQuery,
		listQuery:		listQuery,
		haGetLockValueQuery: 		haGetLockValueQuery,
		haUpsertLockIdentityExec:	haUpsertLockIdentityExec,
		haDeleteLockExec:			haDeleteLockExec,
		logger:			logger,
		permitPool: 	physical.NewPermitPool(maxParInt),
		haEnabled:		conf["ha_enabled"] == "true",
	}

	return m, nil
}

// connectionURL first check the environment variables for a connection URL. If
// no connection URL exists in the environment variable, the Vault config file is
// checked. If neither the environment variables or the config file set the connection
// URL for the ysql backend, because it is a required field, an error is returned.
func connectionURL(conf map[string]string) string {
	connURL := conf["connection_url"]
	if envURL := os.Getenv("VAULT_YSQL_CONNECTION_URL"); envURL != "" {
		connURL = envURL
	}

	return connURL
}

// splitKey is a helper to split a full path key into individual
// parts: parentPath, path, key
func (m *YSQLBackend) splitKey(fullPath string) (string, string, string) {
	var parentPath string
	var path string

	pieces := strings.Split(fullPath, "/")
	depth := len(pieces)
	key := pieces[depth-1]

	if depth == 1 {
		parentPath = ""
		path = "/"
	} else if depth == 2 {
		parentPath = "/"
		path = "/" + pieces[0] + "/"
	} else {
		parentPath = "/" + strings.Join(pieces[:depth-2], "/") + "/"
		path = "/" + strings.Join(pieces[:depth-1], "/") + "/"
	}

	return parentPath, path, key
}

// Put is used to insert or update an entry.
func (m *YSQLBackend) Put(ctx context.Context, entry *physical.Entry) error {
	defer metrics.MeasureSince([]string{"ysql", "put"}, time.Now())

	m.permitPool.Acquire()
	defer m.permitPool.Release()

	parentPath, path, key := m.splitKey(entry.Key)

	_, err := m.client.Exec(m.putQuery, parentPath, path, key, entry.Value)
	if err != nil {
		return fmt.Errorf("put %s %s: %w", path, key, err)
	}
	return nil
}

// Get is used to fetch and entry.
func (m *YSQLBackend) Get(ctx context.Context, fullPath string) (*physical.Entry, error) {
	defer metrics.MeasureSince([]string{"ysql", "get"}, time.Now())

	m.permitPool.Acquire()
	defer m.permitPool.Release()

	_, path, key := m.splitKey(fullPath)

	var result []byte
	err := m.client.QueryRow(m.getQuery, path, key).Scan(&result)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get %s %s: %w", path, key, err)
	}

	ent := &physical.Entry{
		Key:   fullPath,
		Value: result,
	}
	return ent, nil
}

// Delete is used to permanently delete an entry
func (m *YSQLBackend) Delete(ctx context.Context, fullPath string) error {
	defer metrics.MeasureSince([]string{"ysql", "delete"}, time.Now())

	m.permitPool.Acquire()
	defer m.permitPool.Release()

	_, path, key := m.splitKey(fullPath)

	_, err := m.client.Exec(m.deleteQuery, path, key)
	if err != nil {
		return fmt.Errorf("delete %s %s: %w", path, key, err)
	}
	return nil
}

// List is used to list all the keys under a given
// prefix, up to the next prefix.
func (m *YSQLBackend) List(ctx context.Context, prefix string) ([]string, error) {
	defer metrics.MeasureSince([]string{"ysql", "list"}, time.Now())

	m.permitPool.Acquire()
	defer m.permitPool.Release()

	rows, err := m.client.Query(m.listQuery, "/"+prefix)
	if err != nil {
		return nil, fmt.Errorf("list %s: %w", prefix, err)
	}
	defer rows.Close()

	var keys []string
	for rows.Next() {
		var key string
		err = rows.Scan(&key)
		if err != nil {
			return nil, fmt.Errorf("failed to scan rows: %w", err)
		}

		keys = append(keys, key)
	}

	return keys, nil
}

// LockWith is used for mutual exclusion based on the given key.
func (p *YSQLBackend) LockWith(key, value string) (physical.Lock, error) {
	identity, err := uuid.GenerateUUID()
	if err != nil {
		return nil, fmt.Errorf("lockwith %s %s: %w", key, value, err)
	}
	return &YSQLLock{
		backend:       p,
		key:           key,
		value:         value,
		identity:      identity,
		ttlSeconds:    YSQLLockTTLSeconds,
		renewInterval: YSQLLockRenewInterval,
		retryInterval: YSQLLockRetryInterval,
	}, nil
}

func (p *YSQLBackend) HAEnabled() bool {
	return p.haEnabled
}

// Lock tries to acquire the lock by repeatedly trying to create a record in the
// YSQL table. It will block until either the stop channel is closed or
// the lock could be acquired successfully. The returned channel will be closed
// once the lock in the YSQL table cannot be renewed, either due to an
// error speaking to YSQL or because someone else has taken it.
func (l *YSQLLock) Lock(stopCh <-chan struct{}) (<-chan struct{}, error) {
	l.lock.Lock()
	defer l.lock.Unlock()

	var (
		success = make(chan struct{})
		errors  = make(chan error)
		leader  = make(chan struct{})
	)
	// try to acquire the lock asynchronously
	go l.tryToLock(stopCh, success, errors)

	select {
	case <-success:
		// after acquiring it successfully, we must renew the lock periodically
		l.renewTicker = time.NewTicker(l.renewInterval)
		go l.periodicallyRenewLock(leader)
	case err := <-errors:
		return nil, fmt.Errorf("lock : %w", err)
	case <-stopCh:
		return nil, nil
	}

	return leader, nil
}

// Unlock releases the lock by deleting the lock record from the
// YSQL table.
func (l *YSQLLock) Unlock() error {
	pg := l.backend
	pg.permitPool.Acquire()
	defer pg.permitPool.Release()

	if l.renewTicker != nil {
		l.renewTicker.Stop()
	}

	// Delete lock owned by me
	_, err := pg.client.Exec(pg.haDeleteLockExec, l.identity, l.key)
	if err != nil {
		return fmt.Errorf("unlock : %w",err)
	}
	return nil
}

// Value checks whether or not the lock is held by any instance of YSQLLock,
// including this one, and returns the current value.
func (l *YSQLLock) Value() (bool, string, error) {
	pg := l.backend
	pg.permitPool.Acquire()
	defer pg.permitPool.Release()
	var result string
	err := pg.client.QueryRow(pg.haGetLockValueQuery, l.key).Scan(&result)

	switch err {
	case nil:
		return true, result, nil
	case sql.ErrNoRows:
		return false, "", nil
	default:
		return false, "", err

	}
}

// tryToLock tries to create a new item in YSQL every `retryInterval`.
// As long as the item cannot be created (because it already exists), it will
// be retried. If the operation fails due to an error, it is sent to the errors
// channel. When the lock could be acquired successfully, the success channel
// is closed.
func (l *YSQLLock) tryToLock(stop <-chan struct{}, success chan struct{}, errors chan error) {
	ticker := time.NewTicker(l.retryInterval)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			gotlock, err := l.writeItem()
			switch {
			case err != nil:
				errors <- err
				return
			case gotlock:
				close(success)
				return
			}
		}
	}
}

func (l *YSQLLock) periodicallyRenewLock(done chan struct{}) {
	for range l.renewTicker.C {
		gotlock, err := l.writeItem()
		if err != nil || !gotlock {
			close(done)
			l.renewTicker.Stop()
			return
		}
	}
}

// Attempts to put/update the YSQL item using condition expressions to
// evaluate the TTL.  Returns true if the lock was obtained, false if not.
// If false error may be nil or non-nil: nil indicates simply that someone
// else has the lock, whereas non-nil means that something unexpected happened.
func (l *YSQLLock) writeItem() (bool, error) {
	pg := l.backend
	pg.permitPool.Acquire()
	defer pg.permitPool.Release()

	// Try steal lock or update expiry on my lock

	sqlResult, err := pg.client.Exec(pg.haUpsertLockIdentityExec, l.identity, l.key, l.value, l.ttlSeconds)
	if err != nil {
		return false, err
	}
	if sqlResult == nil {
		return false, fmt.Errorf("empty SQL response received")
	}

	ar, err := sqlResult.RowsAffected()
	if err != nil {
		return false, err
	}
	return ar == 1, nil
}
