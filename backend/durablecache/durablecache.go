// Package durablecache is a best-effort, cross-instance L2 cache backed by Azure Table
// Storage, sitting behind the in-memory L1 caches in main.go/geoip/whois. Azure Functions
// (Flex Consumption) scales to zero when idle and scales out under load, so a pure
// in-memory cache is wiped or fragmented far more often than its TTL implies. This package
// gives those lookups a durable, shared point-read/write so a cold instance can still hit
// on data a different (or since-recycled) instance already fetched.
//
// Every failure mode (missing/bad connection string, timeout, table not found, decode
// error) is swallowed here — callers only ever see a cache miss, never an error, matching
// the same best-effort convention already used by geoip.Lookup/whois.Lookup.
package durablecache

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/data/aztables"
)

const requestTimeout = 2 * time.Second

var (
	initOnce      sync.Once
	serviceClient *aztables.ServiceClient

	tableClientsMu sync.Mutex
	tableClients   = make(map[string]*aztables.Client)

	tableInitMu sync.Mutex
	tableInited = make(map[string]bool)
)

// entity is the on-the-wire shape stored in Table Storage. Value carries the
// caller's T, JSON-encoded, so this package doesn't need type parameters at the
// storage layer. ExpiresAt is zero for rows that never expire (the flags table).
type entity struct {
	PartitionKey string
	RowKey       string
	OriginalKey  string
	Value        string
	ExpiresAt    int64
}

// azuriteConnStr is the well-known, publicly documented Azurite/Storage-Emulator
// account key (not a secret — the same fixed devstoreaccount1 key ships with every
// Azurite install). The aztables SDK's NewServiceClientFromConnectionString only
// understands explicit AccountName/AccountKey pairs, unlike the Functions host and
// other Microsoft SDKs, which special-case the "UseDevelopmentStorage=true" shorthand
// that local.settings.json uses — so that shorthand is expanded here before parsing.
const azuriteConnStr = "AccountName=devstoreaccount1;AccountKey=Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==;DefaultEndpointsProtocol=http;TableEndpoint=http://127.0.0.1:10002/devstoreaccount1;"

func client() *aztables.ServiceClient {
	initOnce.Do(func() {
		connStr := os.Getenv("AzureWebJobsStorage")
		if connStr == "" {
			return
		}
		if connStr == "UseDevelopmentStorage=true" {
			connStr = azuriteConnStr
		}
		c, err := aztables.NewServiceClientFromConnectionString(connStr, nil)
		if err != nil {
			return
		}
		serviceClient = c
	})
	return serviceClient
}

func tableClient(table string) *aztables.Client {
	tableClientsMu.Lock()
	tc, ok := tableClients[table]
	tableClientsMu.Unlock()
	if ok {
		return tc
	}

	svc := client()
	if svc == nil {
		return nil
	}
	tc = svc.NewClient(table)

	tableClientsMu.Lock()
	tableClients[table] = tc
	tableClientsMu.Unlock()
	return tc
}

// ensureTable creates table on first use, best-effort. A pre-existing table (the
// common case after the first call) is not an error.
func ensureTable(ctx context.Context, table string) {
	tableInitMu.Lock()
	done := tableInited[table]
	tableInitMu.Unlock()
	if done {
		return
	}

	svc := client()
	if svc == nil {
		return
	}
	_, _ = svc.CreateTable(ctx, table, nil)

	tableInitMu.Lock()
	tableInited[table] = true
	tableInitMu.Unlock()
}

// rowKey hashes key into a value that's always safe as a Table Storage RowKey
// (which disallows '/', '\', '#', '?', and control characters) — callers pass
// natural keys like hostnames, IPs, or arbitrary URLs, and this makes all of
// them safe uniformly rather than requiring each caller to sanitize its own.
func rowKey(key string) string {
	sum := sha256.Sum256([]byte(key))
	return fmt.Sprintf("%x", sum)
}

// Get returns the value stored for (partition, key) in table, or false if it's
// missing, expired, or the durable layer is unavailable for any reason.
func Get[T any](ctx context.Context, table, partition, key string) (T, bool) {
	var zero T

	tc := tableClient(table)
	if tc == nil {
		return zero, false
	}

	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()

	resp, err := tc.GetEntity(ctx, partition, rowKey(key), nil)
	if err != nil {
		return zero, false
	}

	var e entity
	if err := json.Unmarshal(resp.Value, &e); err != nil {
		return zero, false
	}

	if e.ExpiresAt != 0 && time.Now().Unix() > e.ExpiresAt {
		return zero, false
	}

	var value T
	if err := json.Unmarshal([]byte(e.Value), &value); err != nil {
		return zero, false
	}
	return value, true
}

// Set durably stores value for (partition, key) in table. ttl <= 0 means the row
// never expires (used for the flag-image cache). Best-effort: any failure is
// swallowed since this is a cache, not a source of truth.
func Set[T any](ctx context.Context, table, partition, key string, value T, ttl time.Duration) {
	tc := tableClient(table)
	if tc == nil {
		return
	}

	encoded, err := json.Marshal(value)
	if err != nil {
		return
	}

	var expiresAt int64
	if ttl > 0 {
		expiresAt = time.Now().Add(ttl).Unix()
	}

	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()

	ensureTable(ctx, table)

	e := entity{
		PartitionKey: partition,
		RowKey:       rowKey(key),
		OriginalKey:  key,
		Value:        string(encoded),
		ExpiresAt:    expiresAt,
	}
	body, err := json.Marshal(e)
	if err != nil {
		return
	}

	_, _ = tc.UpsertEntity(ctx, body, nil)
}
