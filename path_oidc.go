package jwtauth

import (
	"context"

	oidc "github.com/coreos/go-oidc"
	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"github.com/kalafut/q"
	"golang.org/x/oauth2"
)

func pathOIDC(b *jwtAuthBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: `oidc/callback` + framework.MatchAllRegex("data"),
			Fields: map[string]*framework.FieldSchema{
				"data": {
					Type: framework.TypeString,
				},
			},

			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ReadOperation: b.pathCallback,
			},
		},
		{
			Pattern: `oidc/auth_url`,
			Fields: map[string]*framework.FieldSchema{
				"role": {
					Type:        framework.TypeLowerCaseString,
					Description: "The role to request an OIDC auth code url for.",
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.authCodeURL,
			},
		},
	}
}

func (b *jwtAuthBackend) pathCallback(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	state := b.verify(d.Raw["state"].(string))
	if state == nil {
		return logical.ErrorResponse("expired or missing OAuth state"), nil
	}

	roleName := state.rolename
	role, err := b.role(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return logical.ErrorResponse("role could not be found"), nil
	}

	config, err := b.config(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return logical.ErrorResponse("could not load configuration"), nil
	}

	provider, err := b.getProvider(ctx, config)
	if err != nil {
		return nil, errwrap.Wrapf("error getting provider for login operation: {{err}}", err)
	}

	var oauth2Config = oauth2.Config{
		ClientID:     config.OIDCClientID,
		ClientSecret: config.OIDCClientSecret,
		RedirectURL:  "http://127.0.0.1:8200/v1/auth/jwt/oidc/callback",

		// Discovery returns the OAuth2 endpoints.
		Endpoint: provider.Endpoint(),

		// "openid" is a required scope for OpenID Connect flows.
		Scopes: []string{oidc.ScopeOpenID, "profile", "email"},
	}

	oauth2Token, err := oauth2Config.Exchange(ctx, d.Raw["code"].(string))
	if err != nil {
		return nil, errwrap.Wrapf("error exchanging oidc code: {{err}}", err)
	}

	// Extract the ID Token from OAuth2 token.
	rawToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		panic("no token!")
		// handle missing token
	}

	// Parse and verify ID Token payload.
	allClaims, err := b.verifyToken(ctx, config, role, rawToken)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	// Attempt to fetch information from the /userinfo endpoint and merge it with
	// the existing claims data. A failure to fetch additional information from this
	// endpoint will not invalidate the authorization flow.
	if userinfo, err := provider.UserInfo(ctx, oauth2.StaticTokenSource(oauth2Token)); err == nil {
		userinfo.Claims(&allClaims)
	}

	// TODO: this should be ahead of verify
	if allClaims["nonce"] != state.nonce {
		return logical.ErrorResponse("invalid ID token nonce"), nil
	}

	q.Q(allClaims)

	alias, groupAliases, err := b.createIdentity(allClaims, role)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	resp := &logical.Response{
		Auth: &logical.Auth{
			Policies:     role.Policies,
			DisplayName:  alias.Name,
			Period:       role.Period,
			NumUses:      role.NumUses,
			Alias:        alias,
			GroupAliases: groupAliases,
			InternalData: map[string]interface{}{
				"role": roleName,
			},
			Metadata: map[string]string{
				"role": roleName,
			},
			LeaseOptions: logical.LeaseOptions{
				Renewable: true,
				TTL:       role.TTL,
				MaxTTL:    role.MaxTTL,
			},
			BoundCIDRs: role.BoundCIDRs,
		},
	}

	return resp, nil
}

// authCodeURL returns a URL used for redirection to receive an authorization code.
// This path requires a role name, but because it is unauthenticated, the response to
// invalid or non-OIDC roles will simply be an empty string.
func (b *jwtAuthBackend) authCodeURL(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	authCodeURL := ""

	config, err := b.config(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return logical.ErrorResponse("could not load configuration"), nil
	}

	roleName := d.Get("role").(string)
	if roleName == "" {
		if config.DefaultRole == "" {
			return logical.ErrorResponse("missing role"), nil
		}
		roleName = config.DefaultRole
	}

	role, err := b.role(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}

	if role != nil && role.RoleType == "oidc" {
		provider, err := b.getProvider(ctx, config)
		if err != nil {
			return nil, errwrap.Wrapf("error getting provider for login operation: {{err}}", err)
		}

		// "openid" is a required scope for OpenID Connect flows.
		scopes := append([]string{oidc.ScopeOpenID}, role.OIDCScopes...)

		// Configure an OpenID Connect aware OAuth2 client.
		oauth2Config := oauth2.Config{
			ClientID:     config.OIDCClientID,
			ClientSecret: config.OIDCClientSecret,

			// RedirectURL is intentionally omitted as it will be added by Vault UI
			// TODO: remove for real once UI is ready
			RedirectURL: "vaultserver/v1/auth/jwt/oidc/callback",

			// Discovery returns the OAuth2 endpoints.
			Endpoint: provider.Endpoint(),

			Scopes: scopes,
		}

		state, nonce, err := b.create(roleName)
		if err != nil {
			return nil, errwrap.Wrapf("error generating OAuth state: {{err}}", err)
		}

		authCodeURL = oauth2Config.AuthCodeURL(state, oidc.Nonce(nonce))
	}

	resp := &logical.Response{
		Data: map[string]interface{}{
			"auth_url": authCodeURL,
		},
	}

	return resp, nil
}
