package oobsrv

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rsa"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-appsec/interactsh-lite/oobclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	leveldberrors "github.com/syndtr/goleveldb/leveldb/errors"
)

func testMemoryStorage(t *testing.T) *memoryStorage {
	t.Helper()

	cfg := Config{
		Domains:          []string{"example.com"},
		Eviction:         30,
		EvictionStrategy: EvictionSliding,
	}
	return NewMemoryStorage(cfg, slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
}

func testDiskStorage(t *testing.T) *diskStorage {
	t.Helper()

	cfg := Config{
		Domains:          []string{"example.com"},
		Eviction:         30,
		EvictionStrategy: EvictionSliding,
		Disk:             true,
		DiskPath:         t.TempDir(),
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	ds, err := NewDiskStorage(cfg, logger)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ds.Close() })
	return ds
}

func testRSAKey(t *testing.T) *rsa.PublicKey {
	t.Helper()
	return &testRSAKeyPair(t).PublicKey
}

// decryptTestInteraction decrypts raw AES-256-CTR encrypted bytes (IV || ciphertext).
func decryptTestInteraction(t *testing.T, encrypted []byte, aesKey []byte) string {
	t.Helper()

	require.GreaterOrEqual(t, len(encrypted), aes.BlockSize)

	iv := encrypted[:aes.BlockSize]
	ct := encrypted[aes.BlockSize:]
	block, err := aes.NewCipher(aesKey)
	require.NoError(t, err)

	decrypted := make([]byte, len(ct))
	cipher.NewCTR(block, iv).XORKeyStream(decrypted, ct)
	return string(decrypted)
}

// testGetAndClearInteractions wraps GetSession + handle.GetAndClearInteractions
// into a single call for test convenience.
func testGetAndClearInteractions(tb testing.TB, s Storage, correlationID, secretKey string) ([][]byte, error) {
	tb.Helper()

	handle, err := s.GetSession(correlationID, secretKey)
	if err != nil {
		return nil, err
	}
	return handle.GetAndClearInteractions()
}

// buildStorageWithConfig creates a storage of the same type as s but with custom config.
// Returns the Storage interface and the underlying *memoryStorage for clock manipulation.
func buildStorageWithConfig(t *testing.T, s Storage, cfg Config) (Storage, *memoryStorage) {
	t.Helper()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	if _, ok := s.(*diskStorage); ok {
		cfg.Disk = true
		cfg.DiskPath = t.TempDir()
		ds, err := NewDiskStorage(cfg, logger)
		require.NoError(t, err)
		t.Cleanup(func() { _ = ds.Close() })
		return ds, ds.memoryStorage
	}
	ms := NewMemoryStorage(cfg, logger)
	return ms, ms
}

type storageTest struct {
	name       string
	action     func(*testing.T, Storage)
	assert     func(*testing.T, Storage)
	assertMem  func(*testing.T, *memoryStorage)
	assertDisk func(*testing.T, *diskStorage)
}

var registerTests = []storageTest{
	{
		name: "register/new_registration",
		action: func(t *testing.T, s Storage) {
			t.Helper()
			aesKey, err := s.Register(t.Context(), "testcorrelationid001", testRSAKey(t), "secret1", nil)
			require.NoError(t, err)
			assert.Len(t, aesKey, 32)
		},
		assert: func(t *testing.T, s Storage) {
			t.Helper()
			assert.Equal(t, uint64(1), s.SessionCount())
			assert.Equal(t, uint64(1), s.SessionsTotal())
			assert.Equal(t, uint64(1), s.MissCount())
		},
		assertMem: func(t *testing.T, ms *memoryStorage) {
			t.Helper()
			ms.mu.RLock()
			defer ms.mu.RUnlock()
			assert.Len(t, ms.sessions, 1)
			assert.Equal(t, 1, ms.lruList.Len())
			assert.Contains(t, ms.sessions, "testcorrelationid001")
		},
	},
	{
		name: "register/duplicate_matching_secret",
		action: func(t *testing.T, s Storage) {
			t.Helper()
			pubKey := testRSAKey(t)
			aesKey1, err := s.Register(t.Context(), "testcorrelationid001", pubKey, "secret1", nil)
			require.NoError(t, err)

			aesKey2, err := s.Register(t.Context(), "testcorrelationid001", pubKey, "secret1", nil)
			require.NoError(t, err)
			assert.Equal(t, aesKey1, aesKey2)
		},
		assert: func(t *testing.T, s Storage) {
			t.Helper()
			assert.Equal(t, uint64(1), s.SessionCount())
			assert.Equal(t, uint64(1), s.SessionsTotal())
			assert.Equal(t, uint64(1), s.HitCount())
		},
		assertMem: func(t *testing.T, ms *memoryStorage) {
			t.Helper()
			ms.mu.RLock()
			defer ms.mu.RUnlock()
			// Two registrations, one session - LRU list should have exactly one entry
			assert.Len(t, ms.sessions, 1)
			assert.Equal(t, 1, ms.lruList.Len())
		},
	},
	{
		name: "register/duplicate_wrong_secret",
		action: func(t *testing.T, s Storage) {
			t.Helper()
			pubKey := testRSAKey(t)
			_, err := s.Register(t.Context(), "testcorrelationid001", pubKey, "secret1", nil)
			require.NoError(t, err)

			_, err = s.Register(t.Context(), "testcorrelationid001", pubKey, "wrong-secret", nil)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "correlation-id provided already exists")
		},
		assert: func(t *testing.T, s Storage) {
			t.Helper()
			assert.Equal(t, uint64(1), s.HitCount())
		},
	},
	{
		name: "register/concurrent_registration",
		action: func(t *testing.T, s Storage) {
			t.Helper()
			pubKey := testRSAKey(t)
			var wg sync.WaitGroup
			for i := range 100 {
				wg.Add(1)
				id := fmt.Sprintf("testcorrelationid%02d", i)
				go func() {
					defer wg.Done()
					_, _ = s.Register(t.Context(), id, pubKey, "secret", nil)
				}()
			}
			wg.Wait()
		},
		assertMem: func(t *testing.T, ms *memoryStorage) {
			t.Helper()
			ms.mu.RLock()
			defer ms.mu.RUnlock()
			assert.Equal(t, 100, ms.lruList.Len())
			assert.Len(t, ms.sessions, 100)
			// LRU list must stay consistent with the session map
			assert.Equal(t, len(ms.sessions), ms.lruList.Len())
		},
		assert: func(t *testing.T, s Storage) {
			t.Helper()
			assert.Equal(t, uint64(100), s.SessionCount())
		},
	},
	{
		name: "register/keepalive_preserves_public_key",
		action: func(t *testing.T, s Storage) {
			t.Helper()
			pubKey1 := testRSAKey(t)
			pubKey2 := testRSAKey(t)

			_, err := s.Register(t.Context(), testCorrelationID, pubKey1, "secret", nil)
			require.NoError(t, err)

			// Keep-alive with different pubkey but same secret
			_, err = s.Register(t.Context(), testCorrelationID, pubKey2, "secret", nil)
			require.NoError(t, err)

			handle, err := s.GetSession(testCorrelationID, "secret")
			require.NoError(t, err)
			assert.Equal(t, pubKey1, handle.PublicKey())
		},
		assertMem: func(t *testing.T, ms *memoryStorage) {
			t.Helper()
			ms.mu.RLock()
			defer ms.mu.RUnlock()
			// Two Register calls, only one session
			assert.Len(t, ms.sessions, 1)
			assert.Equal(t, 1, ms.lruList.Len())
		},
	},
	{
		name: "register/expired_different_secret",
		action: func(t *testing.T, s Storage) {
			t.Helper()
			cfg := Config{
				Domains:          []string{"example.com"},
				Eviction:         1,
				EvictionStrategy: EvictionFixed,
			}
			built, ms := buildStorageWithConfig(t, s, cfg)
			pubKey := testRSAKey(t)

			baseTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
			ms.clock = func() time.Time { return baseTime }

			aesKey1, err := built.Register(t.Context(), "testcorrelationid001", pubKey, "secret1", nil)
			require.NoError(t, err)

			// Advance past TTL
			ms.clock = func() time.Time { return baseTime.Add(48 * time.Hour) }

			// Re-register with different secret - expired session evicted
			aesKey2, err := built.Register(t.Context(), "testcorrelationid001", pubKey, "secret2", nil)
			require.NoError(t, err)
			assert.NotEqual(t, aesKey1, aesKey2)
			assert.Equal(t, uint64(1), built.SessionCount())
			assert.Equal(t, uint64(1), built.EvictionCount())

			// New session accessible with new secret
			_, err = built.GetSession("testcorrelationid001", "secret2")
			require.NoError(t, err)

			// Old secret rejected
			_, err = built.GetSession("testcorrelationid001", "secret1")
			require.Error(t, err)
		},
	},
	{
		name: "register/expired_same_secret",
		action: func(t *testing.T, s Storage) {
			t.Helper()
			cfg := Config{
				Domains:          []string{"example.com"},
				Eviction:         1,
				EvictionStrategy: EvictionFixed,
			}
			built, ms := buildStorageWithConfig(t, s, cfg)
			pubKey := testRSAKey(t)

			baseTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
			ms.clock = func() time.Time { return baseTime }

			aesKey1, err := built.Register(t.Context(), "testcorrelationid001", pubKey, "secret1", nil)
			require.NoError(t, err)

			// Advance past TTL
			ms.clock = func() time.Time { return baseTime.Add(48 * time.Hour) }

			// Re-register with same secret - expired session evicted, fresh registration
			aesKey2, err := built.Register(t.Context(), "testcorrelationid001", pubKey, "secret1", nil)
			require.NoError(t, err)
			assert.NotEqual(t, aesKey1, aesKey2)
			assert.Equal(t, uint64(1), built.SessionCount())
			assert.Equal(t, uint64(1), built.EvictionCount())
			assert.Equal(t, uint64(2), built.SessionsTotal())
		},
	},
	{
		// Tests that re-registering a CID clears any stale persisted data
		// (disk: LevelDB, memory: trivially clean).
		name: "register/stale_disk_data_cleared",
		action: func(t *testing.T, s Storage) {
			t.Helper()
			const cid = "testcorrelationid001"
			pubKey := testRSAKey(t)
			_, err := s.Register(t.Context(), cid, pubKey, "secret1", nil)
			require.NoError(t, err)
			require.NoError(t, s.AppendInteraction(cid, []byte(`{"protocol":"http"}`)))
			require.NoError(t, s.Delete(cid, "secret1"))
			_, err = s.Register(t.Context(), cid, pubKey, "secret2", nil)
			require.NoError(t, err)
		},
		assert: func(t *testing.T, s Storage) {
			t.Helper()
			interactions, err := testGetAndClearInteractions(t, s, "testcorrelationid001", "secret2")
			require.NoError(t, err)
			assert.Empty(t, interactions)
		},
		assertDisk: func(t *testing.T, ds *diskStorage) {
			t.Helper()
			_, err := ds.db.Get([]byte("testcorrelationid001"), nil)
			assert.ErrorIs(t, err, leveldberrors.ErrNotFound)
		},
	},
}

var getResponseTests = []storageTest{
	{
		name: "get_response/with_config",
		action: func(t *testing.T, s Storage) {
			t.Helper()
			cfg := &oobclient.ResponseConfig{
				StatusCode: 302,
				Headers:    []string{"Location: https://example.com"},
			}
			_, err := s.Register(t.Context(), "testcorrelationid001", testRSAKey(t), "secret1", cfg)
			require.NoError(t, err)
		},
		assert: func(t *testing.T, s Storage) {
			t.Helper()
			resp := s.GetResponse("testcorrelationid001")
			require.NotNil(t, resp)
			assert.Equal(t, 302, resp.StatusCode)
			assert.Equal(t, []string{"Location: https://example.com"}, resp.Headers)
		},
	},
	{
		name: "get_response/nil_config",
		action: func(t *testing.T, s Storage) {
			t.Helper()
			_, err := s.Register(t.Context(), "testcorrelationid001", testRSAKey(t), "secret1", nil)
			require.NoError(t, err)
		},
		assert: func(t *testing.T, s Storage) {
			t.Helper()
			assert.Nil(t, s.GetResponse("testcorrelationid001"))
		},
	},
	{
		name: "get_response/nonexistent_session",
		assert: func(t *testing.T, s Storage) {
			t.Helper()
			assert.Nil(t, s.GetResponse("nonexistent00000000"))
		},
	},
	{
		name: "get_response/keep_alive_immutable",
		action: func(t *testing.T, s Storage) {
			t.Helper()
			pubKey := testRSAKey(t)
			cfg1 := &oobclient.ResponseConfig{StatusCode: 302, Headers: []string{"Location: https://first.com"}}
			_, err := s.Register(t.Context(), "testcorrelationid001", pubKey, "secret1", cfg1)
			require.NoError(t, err)

			cfg2 := &oobclient.ResponseConfig{StatusCode: 307, Headers: []string{"Location: https://second.com"}}
			_, err = s.Register(t.Context(), "testcorrelationid001", pubKey, "secret1", cfg2)
			require.NoError(t, err)
		},
		assert: func(t *testing.T, s Storage) {
			t.Helper()
			resp := s.GetResponse("testcorrelationid001")
			require.NotNil(t, resp)
			assert.Equal(t, 302, resp.StatusCode)
			assert.Equal(t, []string{"Location: https://first.com"}, resp.Headers)
		},
	},
}

var getSessionTests = []storageTest{
	{
		name: "get_session/valid_session",
		action: func(t *testing.T, s Storage) {
			t.Helper()
			pubKey := testRSAKey(t)
			aesKey, err := s.Register(t.Context(), "testcorrelationid001", pubKey, "secret1", nil)
			require.NoError(t, err)

			handle, err := s.GetSession("testcorrelationid001", "secret1")
			require.NoError(t, err)
			assert.Equal(t, pubKey, handle.PublicKey())
			assert.Equal(t, aesKey, handle.AESKey())
		},
	},
	{
		name: "get_session/missing_correlation_id",
		assert: func(t *testing.T, s Storage) {
			t.Helper()
			_, err := s.GetSession("nonexistent00000000", "secret1")
			require.Error(t, err)
			assert.Equal(t, "could not get correlation-id", err.Error())
		},
	},
	{
		name: "get_session/wrong_secret_key",
		action: func(t *testing.T, s Storage) {
			t.Helper()
			_, err := s.Register(t.Context(), "testcorrelationid001", testRSAKey(t), "secret1", nil)
			require.NoError(t, err)
		},
		assert: func(t *testing.T, s Storage) {
			t.Helper()
			_, err := s.GetSession("testcorrelationid001", "wrong-secret")
			require.Error(t, err)
			assert.Equal(t, "invalid secret key passed for user", err.Error())
		},
	},
	{
		name: "get_session/hit_counter_on_valid_access",
		action: func(t *testing.T, s Storage) {
			t.Helper()
			_, err := s.Register(t.Context(), "testcorrelationid001", testRSAKey(t), "secret1", nil)
			require.NoError(t, err)
			_, err = s.GetSession("testcorrelationid001", "secret1")
			require.NoError(t, err)
		},
		assert: func(t *testing.T, s Storage) {
			t.Helper()
			assert.Equal(t, uint64(1), s.HitCount())
		},
	},
	{
		name: "get_session/lazy_eviction",
		action: func(t *testing.T, s Storage) {
			t.Helper()
			cfg := Config{
				Domains:          []string{"example.com"},
				Eviction:         1,
				EvictionStrategy: EvictionFixed,
			}
			built, ms := buildStorageWithConfig(t, s, cfg)
			pubKey := testRSAKey(t)

			baseTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
			ms.clock = func() time.Time { return baseTime }

			_, err := built.Register(t.Context(), "testcorrelationid001", pubKey, "secret1", nil)
			require.NoError(t, err)
			assert.Equal(t, uint64(1), built.SessionCount())

			// Advance past TTL
			ms.clock = func() time.Time { return baseTime.Add(48 * time.Hour) }

			// HasCorrelationID lazily evicts expired sessions
			assert.False(t, built.HasCorrelationID("testcorrelationid001"))
			assert.Equal(t, uint64(0), built.SessionCount())
			assert.Equal(t, uint64(1), built.EvictionCount())

			// GetSession also returns error (already evicted)
			_, err = built.GetSession("testcorrelationid001", "secret1")
			require.Error(t, err)
			assert.Equal(t, uint64(2), built.MissCount()) // 1 from Register + 1 from GetSession
		},
	},
}

var getAndClearTests = []storageTest{
	{
		name: "get_and_clear/destructive_read",
		action: func(t *testing.T, s Storage) {
			t.Helper()
			_, err := s.Register(t.Context(), "testcorrelationid001", testRSAKey(t), "secret1", nil)
			require.NoError(t, err)
			require.NoError(t, s.AppendInteraction("testcorrelationid001", []byte(`{"protocol":"http"}`)))
			require.NoError(t, s.AppendInteraction("testcorrelationid001", []byte(`{"protocol":"dns"}`)))
		},
		assertMem: func(t *testing.T, ms *memoryStorage) {
			t.Helper()
			ms.mu.RLock()
			sess := ms.sessions["testcorrelationid001"]
			ms.mu.RUnlock()
			require.NotNil(t, sess)
			sess.mu.Lock()
			defer sess.mu.Unlock()
			// Pre-clear: 2 encrypted interactions stored
			assert.Len(t, sess.interactions, 2)
		},
		assertDisk: func(t *testing.T, ds *diskStorage) {
			t.Helper()
			// Pre-clear: LevelDB key exists and is encrypted
			raw, err := ds.db.Get([]byte("testcorrelationid001"), nil)
			require.NoError(t, err)
			assert.NotContains(t, string(raw), `"protocol"`)
		},
		assert: func(t *testing.T, s Storage) {
			t.Helper()
			interactions, err := testGetAndClearInteractions(t, s, "testcorrelationid001", "secret1")
			require.NoError(t, err)
			assert.Len(t, interactions, 2)

			// Second read returns empty
			interactions, err = testGetAndClearInteractions(t, s, "testcorrelationid001", "secret1")
			require.NoError(t, err)
			assert.Empty(t, interactions)
		},
	},
	{
		name: "get_and_clear/empty_session",
		action: func(t *testing.T, s Storage) {
			t.Helper()
			_, err := s.Register(t.Context(), "testcorrelationid001", testRSAKey(t), "secret1", nil)
			require.NoError(t, err)
		},
		assert: func(t *testing.T, s Storage) {
			t.Helper()
			interactions, err := testGetAndClearInteractions(t, s, "testcorrelationid001", "secret1")
			require.NoError(t, err)
			assert.Empty(t, interactions)
		},
	},
	{
		name: "get_and_clear/missing_session_errors",
		assert: func(t *testing.T, s Storage) {
			t.Helper()
			_, err := s.GetSession("nonexistent00000000", "any")
			require.Error(t, err)
			assert.Equal(t, "could not get correlation-id", err.Error())
		},
	},
	{
		name: "get_and_clear/wrong_secret",
		action: func(t *testing.T, s Storage) {
			t.Helper()
			_, err := s.Register(t.Context(), "testcorrelationid001", testRSAKey(t), "secret1", nil)
			require.NoError(t, err)
			require.NoError(t, s.AppendInteraction("testcorrelationid001", []byte(`{"protocol":"http"}`)))

			_, err = s.GetSession("testcorrelationid001", "wrong")
			require.EqualError(t, err, "invalid secret key passed for user")
		},
		assertDisk: func(t *testing.T, ds *diskStorage) {
			t.Helper()
			// Pre-clear: LevelDB key still exists after wrong-secret attempt
			raw, err := ds.db.Get([]byte("testcorrelationid001"), nil)
			require.NoError(t, err)
			assert.NotContains(t, string(raw), `"protocol"`)
		},
		assert: func(t *testing.T, s Storage) {
			t.Helper()
			// Interactions still present after failed attempt
			interactions, err := testGetAndClearInteractions(t, s, "testcorrelationid001", "secret1")
			require.NoError(t, err)
			assert.Len(t, interactions, 1)
		},
	},
	{
		// disk: GetAndClearInteractions errors with "storage closed" after Close.
		// memory: Close is a no-op; GetAndClear still works.
		name: "get_and_clear/storage_closed",
		action: func(t *testing.T, s Storage) {
			t.Helper()
			cfg := Config{
				Domains:          []string{"example.com"},
				Eviction:         30,
				EvictionStrategy: EvictionSliding,
			}
			st, _ := buildStorageWithConfig(t, s, cfg)
			pubKey := testRSAKey(t)

			if ds, ok := st.(*diskStorage); ok {
				_, err := ds.Register(t.Context(), testCorrelationID, pubKey, "secret", nil)
				require.NoError(t, err)
				require.NoError(t, ds.AppendInteraction(testCorrelationID, []byte(`{"protocol":"http"}`)))

				handle, err := ds.GetSession(testCorrelationID, "secret")
				require.NoError(t, err)

				require.NoError(t, ds.Close())

				_, err = handle.GetAndClearInteractions()
				require.EqualError(t, err, "storage closed")
			} else {
				_, err := st.Register(t.Context(), testCorrelationID, pubKey, "secret", nil)
				require.NoError(t, err)
				require.NoError(t, st.AppendInteraction(testCorrelationID, []byte(`{"protocol":"http"}`)))
				require.NoError(t, st.Close())

				interactions, err := testGetAndClearInteractions(t, st, testCorrelationID, "secret")
				require.NoError(t, err)
				assert.Len(t, interactions, 1)
			}
		},
	},
}

var appendTests = []storageTest{
	{
		// action registers and appends but does NOT clear; assertMem/assertDisk
		// inspect pre-clear state; assert does the round-trip read.
		name: "append/basic_append",
		action: func(t *testing.T, s Storage) {
			t.Helper()
			pubKey := testRSAKey(t)
			_, err := s.Register(t.Context(), "testcorrelationid001", pubKey, "secret1", nil)
			require.NoError(t, err)
			require.NoError(t, s.AppendInteraction("testcorrelationid001", []byte(`{"protocol":"http"}`)))
		},
		assertMem: func(t *testing.T, ms *memoryStorage) {
			t.Helper()
			ms.mu.RLock()
			sess := ms.sessions["testcorrelationid001"]
			ms.mu.RUnlock()
			require.NotNil(t, sess)
			sess.mu.Lock()
			defer sess.mu.Unlock()
			// Interaction stored (encrypted) in memory before any GetAndClear
			assert.Len(t, sess.interactions, 1)
		},
		assertDisk: func(t *testing.T, ds *diskStorage) {
			t.Helper()
			// LevelDB key must exist and not contain the plaintext
			raw, err := ds.db.Get([]byte("testcorrelationid001"), nil)
			require.NoError(t, err)
			assert.NotContains(t, string(raw), `"protocol"`)
		},
		assert: func(t *testing.T, s Storage) {
			t.Helper()
			handle, err := s.GetSession("testcorrelationid001", "secret1")
			require.NoError(t, err)
			interactions, err := handle.GetAndClearInteractions()
			require.NoError(t, err)
			require.Len(t, interactions, 1)
			assert.JSONEq(t, `{"protocol":"http"}`, decryptTestInteraction(t, interactions[0], handle.AESKey()))
		},
	},
	{
		name: "append/concurrent_appends",
		action: func(t *testing.T, s Storage) {
			t.Helper()
			_, err := s.Register(t.Context(), testCorrelationID, testRSAKey(t), "secret", nil)
			require.NoError(t, err)

			var wg sync.WaitGroup
			for i := range 50 {
				wg.Add(1)
				go func() {
					defer wg.Done()
					data := []byte(fmt.Sprintf(`{"protocol":"test","unique-id":"%d"}`, i))
					assert.NoError(t, s.AppendInteraction(testCorrelationID, data))
				}()
			}
			wg.Wait()
		},
		assert: func(t *testing.T, s Storage) {
			t.Helper()
			handle, err := s.GetSession(testCorrelationID, "secret")
			require.NoError(t, err)
			aesKey := handle.AESKey()
			interactions, err := handle.GetAndClearInteractions()
			require.NoError(t, err)
			assert.Len(t, interactions, 50)

			// Verify all are decryptable
			for _, enc := range interactions {
				decrypted := decryptTestInteraction(t, enc, aesKey)
				assert.Contains(t, decrypted, `"protocol":"test"`)
			}
		},
	},
	{
		name: "append/missing_session",
		action: func(t *testing.T, s Storage) {
			t.Helper()
			err := s.AppendInteraction("nonexistent00000000", []byte(`{"protocol":"http"}`))
			require.NoError(t, err)
		},
		assert: func(t *testing.T, s Storage) {
			t.Helper()
			assert.Equal(t, uint64(1), s.MissCount())
		},
	},
	{
		name: "append/concurrent_append_and_poll",
		action: func(t *testing.T, s Storage) {
			t.Helper()
			pubKey := testRSAKey(t)
			_, err := s.Register(t.Context(), testCorrelationID, pubKey, "secret", nil)
			require.NoError(t, err)

			const writers = 10
			const writesPerWriter = 20
			totalExpected := writers * writesPerWriter

			var wg sync.WaitGroup
			var totalPolled atomic.Int64

			for range writers {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for range writesPerWriter {
						_ = s.AppendInteraction(testCorrelationID, []byte(`{"protocol":"test"}`))
					}
				}()
			}

			for range 5 {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for range 10 {
						interactions, err := testGetAndClearInteractions(t, s, testCorrelationID, "secret")
						assert.NoError(t, err)
						totalPolled.Add(int64(len(interactions)))
					}
				}()
			}

			wg.Wait()

			// Drain remaining
			remaining, err := testGetAndClearInteractions(t, s, testCorrelationID, "secret")
			require.NoError(t, err)
			totalPolled.Add(int64(len(remaining)))

			assert.Equal(t, int64(totalExpected), totalPolled.Load())
		},
	},
}

var deleteTests = []storageTest{
	{
		name: "delete/successful_delete",
		action: func(t *testing.T, s Storage) {
			t.Helper()
			_, err := s.Register(t.Context(), "testcorrelationid001", testRSAKey(t), "secret1", nil)
			require.NoError(t, err)
			require.NoError(t, s.Delete("testcorrelationid001", "secret1"))
		},
		assertMem: func(t *testing.T, ms *memoryStorage) {
			t.Helper()
			ms.mu.RLock()
			defer ms.mu.RUnlock()
			assert.Empty(t, ms.sessions)
			assert.Zero(t, ms.lruList.Len())
			assert.Empty(t, ms.lruMap)
		},
		assert: func(t *testing.T, s Storage) {
			t.Helper()
			assert.Equal(t, uint64(1), s.HitCount())
			_, err := s.GetSession("testcorrelationid001", "secret1")
			require.Error(t, err)
			assert.Equal(t, "could not get correlation-id", err.Error())
			assert.Equal(t, uint64(0), s.SessionCount())
		},
	},
	{
		name: "delete/wrong_secret_on_delete",
		action: func(t *testing.T, s Storage) {
			t.Helper()
			_, err := s.Register(t.Context(), "testcorrelationid001", testRSAKey(t), "secret1", nil)
			require.NoError(t, err)
			err = s.Delete("testcorrelationid001", "wrong-secret")
			require.Error(t, err)
			assert.Equal(t, "invalid secret key passed for user", err.Error())
		},
		assertMem: func(t *testing.T, ms *memoryStorage) {
			t.Helper()
			ms.mu.RLock()
			defer ms.mu.RUnlock()
			// Session still present after wrong-secret delete attempt
			assert.Len(t, ms.sessions, 1)
			assert.Equal(t, 1, ms.lruList.Len())
		},
		assert: func(t *testing.T, s Storage) {
			t.Helper()
			assert.Equal(t, uint64(1), s.HitCount())
		},
	},
	{
		name: "delete/nonexistent_misses",
		assert: func(t *testing.T, s Storage) {
			t.Helper()
			err := s.Delete("nonexistent00000000", "secret")
			require.Error(t, err)
			assert.Equal(t, uint64(1), s.MissCount())
		},
	},
	{
		name: "delete/session_count_decrements",
		action: func(t *testing.T, s Storage) {
			t.Helper()
			_, err := s.Register(t.Context(), "testcorrelationid001", testRSAKey(t), "secret1", nil)
			require.NoError(t, err)
			require.NoError(t, s.Delete("testcorrelationid001", "secret1"))
		},
		assertMem: func(t *testing.T, ms *memoryStorage) {
			t.Helper()
			ms.mu.RLock()
			defer ms.mu.RUnlock()
			assert.Empty(t, ms.sessions)
			assert.Zero(t, ms.lruList.Len())
		},
		assert: func(t *testing.T, s Storage) {
			t.Helper()
			assert.Equal(t, uint64(0), s.SessionCount())
			assert.Equal(t, uint64(1), s.SessionsTotal())
		},
	},
	{
		name: "delete/calls_onevict",
		action: func(t *testing.T, s Storage) {
			t.Helper()
			// Get the underlying memoryStorage to set onEvict
			var ms *memoryStorage
			switch v := s.(type) {
			case *memoryStorage:
				ms = v
			case *diskStorage:
				ms = v.memoryStorage
			}

			pubKey := testRSAKey(t)
			var evictedID string
			ms.onEvict = func(cid string, _ *Session) { evictedID = cid }

			_, err := s.Register(t.Context(), testCorrelationID, pubKey, "secret", nil)
			require.NoError(t, err)

			err = s.Delete(testCorrelationID, "secret")
			require.NoError(t, err)
			assert.Equal(t, testCorrelationID, evictedID)
		},
		assertMem: func(t *testing.T, ms *memoryStorage) {
			t.Helper()
			ms.mu.RLock()
			defer ms.mu.RUnlock()
			assert.Empty(t, ms.sessions)
			assert.Zero(t, ms.lruList.Len())
		},
	},
}

var hasCIDTests = []storageTest{
	{
		name: "has_cid/registered_id",
		action: func(t *testing.T, s Storage) {
			t.Helper()
			_, err := s.Register(t.Context(), "testcorrelationid001", testRSAKey(t), "secret1", nil)
			require.NoError(t, err)
		},
		assert: func(t *testing.T, s Storage) {
			t.Helper()
			assert.True(t, s.HasCorrelationID("testcorrelationid001"))
		},
	},
	{
		name: "has_cid/unregistered_id",
		assert: func(t *testing.T, s Storage) {
			t.Helper()
			assert.False(t, s.HasCorrelationID("nonexistent00000000"))
		},
	},
	{
		name: "has_cid/expired_returns_false",
		action: func(t *testing.T, s Storage) {
			t.Helper()
			cfg := Config{
				Domains:          []string{"example.com"},
				Eviction:         1,
				EvictionStrategy: EvictionFixed,
			}
			built, ms := buildStorageWithConfig(t, s, cfg)
			pubKey := testRSAKey(t)

			baseTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
			ms.clock = func() time.Time { return baseTime }

			_, err := built.Register(t.Context(), "testcorrelationid001", pubKey, "secret1", nil)
			require.NoError(t, err)
			assert.True(t, built.HasCorrelationID("testcorrelationid001"))

			// Advance past TTL
			ms.clock = func() time.Time { return baseTime.Add(48 * time.Hour) }

			assert.False(t, built.HasCorrelationID("testcorrelationid001"))
			assert.Equal(t, uint64(0), built.SessionCount())
			assert.Equal(t, uint64(1), built.EvictionCount())
		},
	},
}

var evictionTests = []storageTest{
	{
		name: "eviction/lru_eviction_at_capacity",
		action: func(t *testing.T, s Storage) {
			t.Helper()
			pubKey := testRSAKey(t)
			for i := range 5 {
				id := "testcorrelation" + string(rune('a'+i)) + "0000"
				_, err := s.Register(t.Context(), id, pubKey, "secret", nil)
				require.NoError(t, err)
			}
			assert.Equal(t, uint64(5), s.SessionCount())

			// Manually evict LRU (oldest = first registered)
			var ms *memoryStorage
			switch v := s.(type) {
			case *memoryStorage:
				ms = v
			case *diskStorage:
				ms = v.memoryStorage
			}
			ms.mu.Lock()
			ms.evictLRU()
			ms.mu.Unlock()
		},
		assertMem: func(t *testing.T, ms *memoryStorage) {
			t.Helper()
			ms.mu.RLock()
			defer ms.mu.RUnlock()
			assert.Equal(t, 4, ms.lruList.Len())
			assert.Len(t, ms.sessions, 4)
			_, ok := ms.lruMap["testcorrelationa0000"]
			assert.False(t, ok)
			_, ok = ms.lruMap["testcorrelatione0000"]
			assert.True(t, ok)
		},
		assert: func(t *testing.T, s Storage) {
			t.Helper()
			assert.Equal(t, uint64(4), s.SessionCount())
			assert.Equal(t, uint64(1), s.EvictionCount())
			assert.False(t, s.HasCorrelationID("testcorrelationa0000"))
			assert.True(t, s.HasCorrelationID("testcorrelatione0000"))
		},
	},
	{
		name: "eviction/sliding_ttl_reset_on_access",
		action: func(t *testing.T, s Storage) {
			t.Helper()
			cfg := Config{
				Domains:          []string{"example.com"},
				Eviction:         1,
				EvictionStrategy: EvictionSliding,
			}
			built, ms := buildStorageWithConfig(t, s, cfg)
			pubKey := testRSAKey(t)

			baseTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
			ms.clock = func() time.Time { return baseTime }

			_, err := built.Register(t.Context(), "testcorrelationid001", pubKey, "secret1", nil)
			require.NoError(t, err)

			// Advance 23 hours - not expired, access resets TTL
			ms.clock = func() time.Time { return baseTime.Add(23 * time.Hour) }
			_, err = built.GetSession("testcorrelationid001", "secret1")
			require.NoError(t, err)

			// Advance 23 more hours from the new access time (46h total from start)
			ms.clock = func() time.Time { return baseTime.Add(46 * time.Hour) }
			_, err = built.GetSession("testcorrelationid001", "secret1")
			require.NoError(t, err)
		},
	},
	{
		name: "eviction/fixed_ttl_no_reset",
		action: func(t *testing.T, s Storage) {
			t.Helper()
			cfg := Config{
				Domains:          []string{"example.com"},
				Eviction:         1,
				EvictionStrategy: EvictionFixed,
			}
			built, ms := buildStorageWithConfig(t, s, cfg)
			pubKey := testRSAKey(t)

			baseTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
			ms.clock = func() time.Time { return baseTime }

			_, err := built.Register(t.Context(), "testcorrelationid001", pubKey, "secret1", nil)
			require.NoError(t, err)

			// Access at 23h - still valid
			ms.clock = func() time.Time { return baseTime.Add(23 * time.Hour) }
			_, err = built.GetSession("testcorrelationid001", "secret1")
			require.NoError(t, err)

			// Access at 25h - expired (fixed TTL from creation, not last access)
			ms.clock = func() time.Time { return baseTime.Add(25 * time.Hour) }
			_, err = built.GetSession("testcorrelationid001", "secret1")
			require.Error(t, err)
			assert.Equal(t, "could not get correlation-id", err.Error())
		},
	},
	{
		name: "eviction/no_eviction_disables_ttl",
		action: func(t *testing.T, s Storage) {
			t.Helper()
			cfg := Config{
				Domains:          []string{"example.com"},
				Eviction:         1,
				NoEviction:       true,
				EvictionStrategy: EvictionSliding,
			}
			built, ms := buildStorageWithConfig(t, s, cfg)
			pubKey := testRSAKey(t)

			baseTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
			ms.clock = func() time.Time { return baseTime }

			_, err := built.Register(t.Context(), "testcorrelationid001", pubKey, "secret1", nil)
			require.NoError(t, err)

			// Way past TTL - but noEviction prevents expiry
			ms.clock = func() time.Time { return baseTime.Add(365 * 24 * time.Hour) }
			_, err = built.GetSession("testcorrelationid001", "secret1")
			require.NoError(t, err)
		},
	},
	{
		name: "eviction/lru_promotion_on_keep_alive",
		action: func(t *testing.T, s Storage) {
			t.Helper()
			pubKey := testRSAKey(t)

			// Register A, B, C in order
			_, err := s.Register(t.Context(), "aaaaaaaaaaaaaaaaaaaa", pubKey, "secret", nil)
			require.NoError(t, err)
			_, err = s.Register(t.Context(), "bbbbbbbbbbbbbbbbbbbb", pubKey, "secret", nil)
			require.NoError(t, err)
			_, err = s.Register(t.Context(), "cccccccccccccccccccc", pubKey, "secret", nil)
			require.NoError(t, err)

			// Keep-alive A - promotes to back of LRU
			_, err = s.Register(t.Context(), "aaaaaaaaaaaaaaaaaaaa", pubKey, "secret", nil)
			require.NoError(t, err)

			// Evict LRU - should evict B (oldest non-promoted), not A
			var ms *memoryStorage
			switch v := s.(type) {
			case *memoryStorage:
				ms = v
			case *diskStorage:
				ms = v.memoryStorage
			}
			ms.mu.Lock()
			ms.evictLRU()
			ms.mu.Unlock()
		},
		assertMem: func(t *testing.T, ms *memoryStorage) {
			t.Helper()
			ms.mu.RLock()
			defer ms.mu.RUnlock()
			assert.Equal(t, 2, ms.lruList.Len())
			assert.Len(t, ms.sessions, 2)
		},
		assert: func(t *testing.T, s Storage) {
			t.Helper()
			assert.True(t, s.HasCorrelationID("aaaaaaaaaaaaaaaaaaaa"))
			assert.False(t, s.HasCorrelationID("bbbbbbbbbbbbbbbbbbbb"))
			assert.True(t, s.HasCorrelationID("cccccccccccccccccccc"))
		},
	},
	{
		name: "eviction/concurrent_register_at_capacity",
		action: func(t *testing.T, s Storage) {
			t.Helper()
			cfg := Config{
				Domains:          []string{"example.com"},
				Eviction:         30,
				EvictionStrategy: EvictionSliding,
			}
			built, ms := buildStorageWithConfig(t, s, cfg)

			// Register 5 sessions
			for i := range 5 {
				id := fmt.Sprintf("cid_%020d", i)
				_, err := built.Register(t.Context(), id, testRSAKey(t), "secret", nil)
				require.NoError(t, err)
			}

			newKey := testRSAKey(t)
			var wg sync.WaitGroup
			wg.Add(2)
			go func() {
				defer wg.Done()
				ms.mu.Lock()
				ms.evictLRU()
				ms.mu.Unlock()
			}()
			go func() {
				defer wg.Done()
				_, _ = built.Register(t.Context(), "newcid_00000000000000", newKey, "secret", nil)
			}()
			wg.Wait()

			assert.GreaterOrEqual(t, built.EvictionCount(), uint64(1))
		},
	},
	{
		name: "eviction/sliding_ttl_concurrent_keepalive",
		action: func(t *testing.T, s Storage) {
			t.Helper()
			cfg := Config{
				Domains:          []string{"example.com"},
				Eviction:         30,
				EvictionStrategy: EvictionSliding,
			}
			built, ms := buildStorageWithConfig(t, s, cfg)
			ms.ttl = 24 * time.Hour
			pubKey := testRSAKey(t)

			baseTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
			ms.clock = func() time.Time { return baseTime }

			aesKey, err := built.Register(t.Context(), testCorrelationID, pubKey, "secret", nil)
			require.NoError(t, err)

			// Advance to 23h and do concurrent keep-alives
			ms.clock = func() time.Time { return baseTime.Add(23 * time.Hour) }

			var wg sync.WaitGroup
			for range 10 {
				wg.Add(1)
				go func() {
					defer wg.Done()
					got, err := built.Register(t.Context(), testCorrelationID, pubKey, "secret", nil)
					if assert.NoError(t, err) {
						assert.Equal(t, aesKey, got)
					}
				}()
			}
			wg.Wait()

			// Advance to 47h - would expire from creation (47h > 24h) but
			// sliding TTL was refreshed at 23h, so 47h - 23h = 24h which is not > 24h
			ms.clock = func() time.Time { return baseTime.Add(47 * time.Hour) }
			_, err = built.GetSession(testCorrelationID, "secret")
			assert.NoError(t, err)
		},
	},
	{
		name: "eviction/fixed_ttl_exact_boundary",
		action: func(t *testing.T, s Storage) {
			t.Helper()
			cfg := Config{
				Domains:          []string{"example.com"},
				Eviction:         30,
				EvictionStrategy: EvictionSliding,
			}
			built, ms := buildStorageWithConfig(t, s, cfg)
			ms.slidingTTL = false
			ms.ttl = 24 * time.Hour
			pubKey := testRSAKey(t)

			baseTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
			ms.clock = func() time.Time { return baseTime }

			_, err := built.Register(t.Context(), testCorrelationID, pubKey, "secret", nil)
			require.NoError(t, err)

			// At exactly 24h: Sub == TTL, so > is false -> NOT expired
			ms.clock = func() time.Time { return baseTime.Add(24 * time.Hour) }
			_, err = built.GetSession(testCorrelationID, "secret")
			require.NoError(t, err)

			// At 24h + 1ns: Sub > TTL -> expired
			ms.clock = func() time.Time { return baseTime.Add(24*time.Hour + time.Nanosecond) }
			_, err = built.GetSession(testCorrelationID, "secret")
			assert.Error(t, err)
		},
	},
	{
		name: "eviction/deletes_leveldb_key",
		action: func(t *testing.T, s Storage) {
			t.Helper()
			pubKey := testRSAKey(t)
			_, err := s.Register(t.Context(), "testcorrelationid001", pubKey, "secret1", nil)
			require.NoError(t, err)
			require.NoError(t, s.AppendInteraction("testcorrelationid001", []byte("data")))

			// Get the underlying memoryStorage for direct evictLRU call
			var ms *memoryStorage
			switch v := s.(type) {
			case *memoryStorage:
				ms = v
			case *diskStorage:
				ms = v.memoryStorage
			}

			ms.mu.Lock()
			ms.evictLRU()
			ms.mu.Unlock()

			assert.False(t, s.HasCorrelationID("testcorrelationid001"))
		},
		assertMem: func(t *testing.T, ms *memoryStorage) {
			t.Helper()
			ms.mu.RLock()
			defer ms.mu.RUnlock()
			assert.Empty(t, ms.sessions)
			assert.Zero(t, ms.lruList.Len())
			assert.Empty(t, ms.lruMap)
		},
		assertDisk: func(t *testing.T, ds *diskStorage) {
			t.Helper()
			// LevelDB key deleted by onEvict callback
			_, err := ds.db.Get([]byte("testcorrelationid001"), nil)
			require.ErrorIs(t, err, leveldberrors.ErrNotFound)

			// Embedded memoryStorage also cleaned up
			ds.mu.RLock()
			defer ds.mu.RUnlock()
			assert.Empty(t, ds.sessions)
			assert.Zero(t, ds.lruList.Len())
			assert.Empty(t, ds.lruMap)
		},
	},
}

func buildStorageTestCases() []storageTest {
	groups := [][]storageTest{
		registerTests, getResponseTests, getSessionTests, getAndClearTests,
		appendTests, deleteTests, hasCIDTests,
		evictionTests,
	}
	var total int
	for _, g := range groups {
		total += len(g)
	}
	all := make([]storageTest, 0, total)
	for _, g := range groups {
		all = append(all, g...)
	}
	return all
}

func TestStorageMem(t *testing.T) {
	t.Parallel()

	for _, tc := range buildStorageTestCases() {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			runStorageTest(t, tc, testMemoryStorage(t))
		})
	}
}

func TestStorageDisk(t *testing.T) {
	t.Parallel()

	for _, tc := range buildStorageTestCases() {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			runStorageTest(t, tc, testDiskStorage(t))
		})
	}
}

func runStorageTest(t *testing.T, tc storageTest, s Storage) {
	t.Helper()
	if tc.action != nil {
		tc.action(t, s)
	}
	if tc.assertMem != nil {
		if ms, ok := s.(*memoryStorage); ok {
			tc.assertMem(t, ms)
		}
	}
	if tc.assertDisk != nil {
		if ds, ok := s.(*diskStorage); ok {
			tc.assertDisk(t, ds)
		}
	}
	if tc.assert != nil {
		tc.assert(t, s)
	}
}

func TestSharedBucketAppend(t *testing.T) {
	t.Parallel()

	t.Run("fifo_order", func(t *testing.T) {
		b := NewSharedBucket(100, 24*time.Hour)
		b.Append([]byte("first"))
		b.Append([]byte("second"))
		b.Append([]byte("third"))

		result := b.ReadFrom("consumer1")
		assert.Equal(t, [][]byte{[]byte("first"), []byte("second"), []byte("third")}, result)
	})

	t.Run("max_buffer_drops_oldest", func(t *testing.T) {
		// maxBuffer=3, halve triggers at 2*3=6 items
		b := NewSharedBucket(3, 24*time.Hour)

		// Consumer reads first 2
		b.Append([]byte("a"))
		b.Append([]byte("b"))
		b.ReadFrom("consumer1") // offset = 2

		// Fill to 2*maxBuffer to trigger halve (drops oldest 3: a,b,c)
		b.Append([]byte("c"))
		b.Append([]byte("d"))
		b.Append([]byte("e"))
		b.Append([]byte("f")) // total=6, triggers halve -> keeps d,e,f

		// Consumer1 offset was 2, adjusted to max(0, 2-3) = 0
		result := b.ReadFrom("consumer1")
		assert.Equal(t, [][]byte{[]byte("d"), []byte("e"), []byte("f")}, result)

		// New consumer sees all 3 remaining
		result = b.ReadFrom("consumer2")
		assert.Equal(t, [][]byte{[]byte("d"), []byte("e"), []byte("f")}, result)
	})

	t.Run("multi_consumer_offset_adjustment", func(t *testing.T) {
		// maxBuffer=3, halve triggers at 6 items
		b := NewSharedBucket(3, time.Hour)

		b.Append([]byte("a"))
		b.Append([]byte("b"))

		// Both consumers read all 2 items
		a := b.ReadFrom("A")
		require.Len(t, a, 2)
		_ = b.ReadFrom("B")

		// Append 4 more (total 6, triggers halve -> drops a,b,c -> keeps d,e,f)
		b.Append([]byte("c"))
		b.Append([]byte("d"))
		b.Append([]byte("e"))
		b.Append([]byte("f"))

		// Consumer A had offset=2, after halve: max(0, 2-3) = 0, sees d,e,f
		resultA := b.ReadFrom("A")
		assert.Equal(t, [][]byte{[]byte("d"), []byte("e"), []byte("f")}, resultA)

		// Consumer B had offset=2, after halve: max(0, 2-3) = 0, sees d,e,f
		resultB := b.ReadFrom("B")
		assert.Equal(t, [][]byte{[]byte("d"), []byte("e"), []byte("f")}, resultB)
	})
}

func TestSharedBucketReadFrom(t *testing.T) {
	t.Parallel()

	t.Run("per_consumer_offsets", func(t *testing.T) {
		b := NewSharedBucket(100, 24*time.Hour)
		b.Append([]byte("interaction1"))
		b.Append([]byte("interaction2"))

		// Consumer A reads all
		resultA := b.ReadFrom("consumerA")
		assert.Len(t, resultA, 2)

		// Consumer B also reads all (independent offset)
		resultB := b.ReadFrom("consumerB")
		assert.Len(t, resultB, 2)

		// Append more
		b.Append([]byte("interaction3"))

		// Both get only the new one
		resultA = b.ReadFrom("consumerA")
		assert.Equal(t, [][]byte{[]byte("interaction3")}, resultA)

		resultB = b.ReadFrom("consumerB")
		assert.Equal(t, [][]byte{[]byte("interaction3")}, resultB)
	})

	t.Run("triggers_stale_cleanup", func(t *testing.T) {
		b := NewSharedBucket(100, 1*time.Hour)
		b.Append([]byte("interaction1"))

		// Establish two consumers
		b.ReadFrom("stale-consumer")
		b.ReadFrom("active-consumer")

		// Backdate stale consumer and lastCleanup to trigger cleanup
		b.mu.Lock()
		b.lastSeen["stale-consumer"] = time.Now().Add(-2 * time.Hour)
		b.lastCleanup = time.Now().Add(-2 * time.Minute)
		b.mu.Unlock()

		// Active consumer reads - triggers reactive cleanup
		b.ReadFrom("active-consumer")

		b.mu.RLock()
		_, staleExists := b.offsets["stale-consumer"]
		_, activeExists := b.offsets["active-consumer"]
		b.mu.RUnlock()

		assert.False(t, staleExists)
		assert.True(t, activeExists)
	})

	t.Run("no_new_data_returns_nil", func(t *testing.T) {
		b := NewSharedBucket(100, 24*time.Hour)
		b.Append([]byte("interaction1"))

		// First read consumes everything
		result := b.ReadFrom("consumer1")
		require.Len(t, result, 1)

		// Second read with no new data
		result = b.ReadFrom("consumer1")
		assert.Nil(t, result)
	})
}

func TestDiskStorageClose(t *testing.T) {
	t.Parallel()

	t.Run("removes_db_directory", func(t *testing.T) {
		tmpDir := t.TempDir()
		cfg := Config{
			Domains:          []string{"example.com"},
			Eviction:         30,
			EvictionStrategy: EvictionSliding,
			Disk:             true,
			DiskPath:         tmpDir,
		}
		logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

		ds, err := NewDiskStorage(cfg, logger)
		require.NoError(t, err)

		dbPath := ds.dbPath
		_, err = os.Stat(dbPath)
		require.NoError(t, err)

		require.NoError(t, ds.Close())

		_, err = os.Stat(dbPath)
		assert.True(t, os.IsNotExist(err))
	})
}
