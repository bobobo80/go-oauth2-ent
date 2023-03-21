package oauth2ent

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"time"

	entsql "entgo.io/ent/dialect/sql"
	"github.com/bobobo80/go-oauth2-ent/ent"
	"github.com/bobobo80/go-oauth2-ent/ent/oauthtoken"
	"github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/models"
)

const (
	DefaultInterval = 600
)

type Store struct {
	client *ent.Client
	ticker *time.Ticker
	stdout io.Writer
}

func NewStoreWithDB(ctx context.Context, db *sql.DB, gcInterval int, dialect string) (*Store, error) {
	driver := entsql.OpenDB(dialect, db)
	client := ent.NewClient(ent.Driver(driver))
	return NewStoreWithClient(ctx, client, gcInterval, dialect)
}

func NewStoreWithClient(ctx context.Context, client *ent.Client, gcInterval int, dialect string) (*Store, error) {
	store := &Store{
		client: client,
	}
	if err := store.client.Schema.Create(ctx); err != nil {
		return nil, err
	}

	if gcInterval <= 0 {
		gcInterval = DefaultInterval
	}
	store.ticker = time.NewTicker(time.Second * time.Duration(gcInterval))
	go store.gc(ctx)
	return store, nil
}

func (s *Store) Close() {
	s.ticker.Stop()
	s.client.Close()
}

func (s *Store) errorf(format string, args ...interface{}) {
	if s.stdout != nil {
		buf := fmt.Sprintf("[OAUTH2-ENT-ERROR]: "+format, args...)
		_, _ = s.stdout.Write([]byte(buf))
	}
}

func (s *Store) gc(ctx context.Context) {
	for range s.ticker.C {
		s.clean(ctx)
	}
}

func (s *Store) clean(ctx context.Context) {
	now := time.Now()
	n, err := s.client.OAuthToken.Query().Where(
		oauthtoken.Or(
			oauthtoken.ExpiredAtLTE(now)),
		oauthtoken.And(
			oauthtoken.CodeEQ(""),
			oauthtoken.AccessEQ(""),
			oauthtoken.RefreshEQ(""),
		),
	).Count(ctx)
	if err != nil || n == 0 {
		if err != nil {
			s.errorf(err.Error())
		}
		return
	}

	// TODO may add limit
	_, err = s.client.OAuthToken.Delete().Where(
		oauthtoken.Or(
			oauthtoken.ExpiredAtLTE(now)),
		oauthtoken.And(
			oauthtoken.CodeEQ(""),
			oauthtoken.AccessEQ(""),
			oauthtoken.RefreshEQ(""),
		),
	).Exec(ctx)
	if err != nil {
		s.errorf(err.Error())
	}
}

// Create create and store the new token information
func (s *Store) Create(ctx context.Context, info oauth2.TokenInfo) error {
	buf, _ := json.Marshal(info)
	token := s.client.OAuthToken.Create()
	token.SetData(string(buf))

	if code := info.GetCode(); code != "" {
		token.SetCode(code)
		token.SetExpiredAt(info.GetCodeCreateAt().Add(info.GetCodeExpiresIn()))
	} else {
		token.SetAccess(info.GetAccess())
		token.SetExpiredAt(info.GetAccessCreateAt().Add(info.GetAccessExpiresIn()))

		if refresh := info.GetRefresh(); refresh != "" {
			token.SetRefresh(info.GetRefresh())
			token.SetExpiredAt(info.GetRefreshCreateAt().Add(info.GetRefreshExpiresIn()))
		}
	}

	_, err := token.Save(ctx)
	return err
}

// RemoveByCode delete the authorization code
func (s *Store) RemoveByCode(ctx context.Context, code string) error {
	err := s.client.OAuthToken.
		Update().
		SetCode("").
		Where(
			oauthtoken.CodeEQ(code),
		).
		Exec(ctx)
	if ent.IsNotFound(err) {
		return nil
	}
	return err
}

// RemoveByAccess use the access token to delete the token information
func (s *Store) RemoveByAccess(ctx context.Context, access string) error {
	err := s.client.OAuthToken.Update().
		SetAccess("").
		Where(
			oauthtoken.AccessEQ(access),
		).
		Exec(ctx)

	if ent.IsNotFound(err) {
		return nil
	}
	return err
}

// RemoveByRefresh use the refresh token to delete the token information
func (s *Store) RemoveByRefresh(ctx context.Context, refresh string) error {
	err := s.client.OAuthToken.Update().
		SetRefresh("").
		Where(
			oauthtoken.RefreshEQ(refresh),
		).
		Exec(ctx)

	if ent.IsNotFound(err) {
		return nil
	}
	return err
}

func (s *Store) toTokenInfo(data string) (oauth2.TokenInfo, error) {
	var tm models.Token
	err := json.Unmarshal([]byte(data), &tm)
	return &tm, err
}

// GetByCode use the authorization code for token information data
func (s *Store) GetByCode(ctx context.Context, code string) (oauth2.TokenInfo, error) {
	if code == "" {
		return nil, nil
	}

	token, err := s.client.OAuthToken.Query().Where(oauthtoken.CodeEQ(code)).First(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	return s.toTokenInfo(token.Data)
}

// GetByAccess use the access token for token information data
func (s *Store) GetByAccess(ctx context.Context, access string) (oauth2.TokenInfo, error) {
	if access == "" {
		return nil, nil
	}

	token, err := s.client.OAuthToken.Query().Where(oauthtoken.Access(access)).First(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	return s.toTokenInfo(token.Data)
}

// GetByRefresh use the refresh token for token information data
func (s *Store) GetByRefresh(ctx context.Context, refresh string) (oauth2.TokenInfo, error) {
	if refresh == "" {
		return nil, nil
	}

	token, err := s.client.OAuthToken.Query().Where(oauthtoken.RefreshEQ(refresh)).First(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	return s.toTokenInfo(token.Data)
}
