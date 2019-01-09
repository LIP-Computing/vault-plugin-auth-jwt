package jwtauth

import (
	"context"
	"sync"
	"time"

	oidc "github.com/coreos/go-oidc"
	"github.com/hashicorp/vault/helper/base62"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"github.com/kalafut/q"
)

const (
	configPath string = "config"
	rolePrefix string = "role/"
)

var oidcStateTimeout = 2 * time.Minute

// Factory is used by framework
func Factory(ctx context.Context, c *logical.BackendConfig) (logical.Backend, error) {
	b := backend(c)
	if err := b.Setup(ctx, c); err != nil {
		return nil, err
	}
	return b, nil
}

type jwtAuthBackend struct {
	*framework.Backend

	l            sync.RWMutex
	provider     *oidc.Provider
	cachedConfig *jwtConfig
	oidcStates   map[string]*oidcState

	providerCtx       context.Context
	providerCtxCancel context.CancelFunc
}

func backend(c *logical.BackendConfig) *jwtAuthBackend {
	b := new(jwtAuthBackend)
	b.providerCtx, b.providerCtxCancel = context.WithCancel(context.Background())
	b.oidcStates = make(map[string]*oidcState)

	b.Backend = &framework.Backend{
		AuthRenew:   b.pathLoginRenew,
		BackendType: logical.TypeCredential,
		Invalidate:  b.invalidate,
		Help:        backendHelp,
		PathsSpecial: &logical.Paths{
			Unauthenticated: []string{
				"login",
				"ui",
				"oidc/auth_url",
				"oidc/callback",
			},
			SealWrapStorage: []string{
				"config",
			},
		},
		Paths: framework.PathAppend(
			[]*framework.Path{
				pathLogin(b),
				pathRoleList(b),
				pathRole(b),
				pathConfig(b),
				pathUI(b),
			},
			pathOIDC(b),
		),
		Clean: b.cleanup,
	}

	// Start a periodic cleanup of unused state tokens
	go func() {
		for {
			b.cleanStates()
			time.Sleep(1 * time.Minute)
		}
	}()

	return b
}

func (b *jwtAuthBackend) cleanup(_ context.Context) {
	b.l.Lock()
	if b.providerCtxCancel != nil {
		b.providerCtxCancel()
	}
	b.l.Unlock()
}

func (b *jwtAuthBackend) invalidate(ctx context.Context, key string) {
	switch key {
	case "config":
		b.reset()
	}
}

func (b *jwtAuthBackend) reset() {
	b.l.Lock()
	b.provider = nil
	b.cachedConfig = nil
	b.l.Unlock()
}

func (b *jwtAuthBackend) getProvider(ctx context.Context, config *jwtConfig) (*oidc.Provider, error) {
	b.l.RLock()
	unlockFunc := b.l.RUnlock
	defer func() { unlockFunc() }()

	if b.provider != nil {
		return b.provider, nil
	}

	b.l.RUnlock()
	b.l.Lock()
	unlockFunc = b.l.Unlock

	if b.provider != nil {
		return b.provider, nil
	}

	provider, err := b.createProvider(config)
	if err != nil {
		return nil, err
	}

	b.provider = provider
	return provider, nil
}

type oidcState struct {
	rolename   string
	expiration time.Time
	nonce      string
}

// createOIDCState generates a random, expiring state token.
func (b *jwtAuthBackend) create(rolename string) (string, string, error) {
	randstr, err := base62.Random(40)
	if err != nil {
		return "", "", err
	}

	state, nonce := randstr[0:20], randstr[20:]

	b.l.Lock()
	b.oidcStates[state] = &oidcState{
		rolename:   rolename,
		expiration: time.Now().Add(oidcStateTimeout),
		nonce:      nonce,
	}
	b.l.Unlock()

	return state, nonce, nil
}

// verifyOIDCState tests that the provided state token is valid.
// The state token is delete as part of the query.
func (b *jwtAuthBackend) verify(state string) *oidcState {
	b.l.Lock()
	defer b.l.Unlock()

	s := b.oidcStates[state]
	if s != nil && time.Now().After(s.expiration) {
		s = nil
	}

	delete(b.oidcStates, state)

	return s
}

func (b *jwtAuthBackend) cleanStates() {
	b.l.Lock()

	// delete any expired state tokens
	now := time.Now()
	for k := range b.oidcStates {
		if now.After(b.oidcStates[k].expiration) {
			q.Q("cleaning unused token", k)
			delete(b.oidcStates, k)
		}
	}
	b.l.Unlock()
}

const (
	backendHelp = `
The JWT backend plugin allows authentication using JWTs (including OIDC).
`
)
