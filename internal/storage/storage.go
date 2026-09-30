package storage

import (
	"errors"
	"fmt"
	"go-port-forward/internal/models"
	"go-port-forward/pkg/serializer/json"
	"time"

	bolt "go.etcd.io/bbolt"
)

var (
	rulesBucket     = []byte("rules")
	upstreamsBucket = []byte("upstreams")
)

var (
	// ErrRuleNotFound indicates the requested rule does not exist in storage.
	ErrRuleNotFound = errors.New("rule not found")
	// ErrUpstreamNotFound indicates the requested upstream does not exist in storage.
	ErrUpstreamNotFound = errors.New("upstream not found")
)

// Store provides persistent storage for forwarding rules and upstream groups.
type Store interface {
	ListRules() ([]*models.ForwardRule, error)
	GetRule(id string) (*models.ForwardRule, error)
	SaveRule(rule *models.ForwardRule) error
	DeleteRule(id string) error
	ListUpstreams() ([]*models.Upstream, error)
	GetUpstream(id string) (*models.Upstream, error)
	SaveUpstream(upstream *models.Upstream) error
	DeleteUpstream(id string) error
	Close() error
}

type boltStore struct {
	db *bolt.DB
}

// Open opens (or creates) the bbolt database at path.
func Open(path string) (Store, error) {
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 2 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("storage: open %s: %w", path, err)
	}
	// Ensure buckets exist
	if err = db.Update(func(tx *bolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists(rulesBucket); err != nil {
			return err
		}
		_, err := tx.CreateBucketIfNotExists(upstreamsBucket)
		return err
	}); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &boltStore{db: db}, nil
}

func (s *boltStore) ListRules() ([]*models.ForwardRule, error) {
	var rules []*models.ForwardRule
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(rulesBucket)
		return b.ForEach(func(_, v []byte) error {
			var r models.ForwardRule
			if err := json.Unmarshal(v, &r); err != nil {
				return err
			}
			scrubRuntimeFields(&r)
			rules = append(rules, &r)
			return nil
		})
	})
	return rules, err
}

func (s *boltStore) GetRule(id string) (*models.ForwardRule, error) {
	var rule models.ForwardRule
	err := s.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(rulesBucket).Get([]byte(id))
		if v == nil {
			return fmt.Errorf("%w: %s", ErrRuleNotFound, id)
		}
		if err := json.Unmarshal(v, &rule); err != nil {
			return err
		}
		scrubRuntimeFields(&rule)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &rule, nil
}

func (s *boltStore) SaveRule(rule *models.ForwardRule) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		persisted := *rule
		scrubRuntimeFields(&persisted)
		data, err := json.Marshal(&persisted)
		if err != nil {
			return err
		}
		return tx.Bucket(rulesBucket).Put([]byte(rule.ID), data)
	})
}

func (s *boltStore) DeleteRule(id string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(rulesBucket)
		if b.Get([]byte(id)) == nil {
			return fmt.Errorf("%w: %s", ErrRuleNotFound, id)
		}
		return b.Delete([]byte(id))
	})
}

func scrubRuntimeFields(rule *models.ForwardRule) {
	if rule == nil {
		return
	}
	rule.Status = ""
	rule.ErrorMsg = ""
	rule.GroupName = ""
	rule.GroupServerCount = 0
}

// --- upstreams ---

// ListUpstreams returns all persisted upstream groups.
func (s *boltStore) ListUpstreams() ([]*models.Upstream, error) {
	var upstreams []*models.Upstream
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(upstreamsBucket)
		return b.ForEach(func(_, v []byte) error {
			var u models.Upstream
			if err := json.Unmarshal(v, &u); err != nil {
				return err
			}
			scrubUpstreamRuntimeFields(&u)
			upstreams = append(upstreams, &u)
			return nil
		})
	})
	return upstreams, err
}

// GetUpstream returns one persisted upstream group by ID.
func (s *boltStore) GetUpstream(id string) (*models.Upstream, error) {
	var upstream models.Upstream
	err := s.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(upstreamsBucket).Get([]byte(id))
		if v == nil {
			return fmt.Errorf("%w: %s", ErrUpstreamNotFound, id)
		}
		if err := json.Unmarshal(v, &upstream); err != nil {
			return err
		}
		scrubUpstreamRuntimeFields(&upstream)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &upstream, nil
}

// SaveUpstream persists an upstream group (runtime fields scrubbed).
func (s *boltStore) SaveUpstream(upstream *models.Upstream) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		persisted := *upstream
		scrubUpstreamRuntimeFields(&persisted)
		data, err := json.Marshal(&persisted)
		if err != nil {
			return err
		}
		return tx.Bucket(upstreamsBucket).Put([]byte(upstream.ID), data)
	})
}

// DeleteUpstream removes an upstream group permanently.
func (s *boltStore) DeleteUpstream(id string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(upstreamsBucket)
		if b.Get([]byte(id)) == nil {
			return fmt.Errorf("%w: %s", ErrUpstreamNotFound, id)
		}
		return b.Delete([]byte(id))
	})
}

func scrubUpstreamRuntimeFields(u *models.Upstream) {
	if u == nil {
		return
	}
	u.ServerStats = nil
}

func (s *boltStore) Close() error { return s.db.Close() }
