package oauth2ent

import (
	"context"
	"testing"
	"time"

	"github.com/bobobo80/go-oauth2-ent/ent"
	"github.com/bobobo80/go-oauth2-ent/ent/enttest"
	"github.com/go-oauth2/oauth2/v4/models"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/suite"
)

type CreateTokenTestSuite struct {
	suite.Suite

	ctx       context.Context
	client    *ent.Client
	tokenInfo *models.Token

	dialect string
	dsn     string
}

func TestRunCreateTokenTestSuite(t *testing.T) {
	suite.Run(t, new(CreateTokenTestSuite))
}

func (s *CreateTokenTestSuite) SetupTest() {
	s.ctx = context.Background()

	s.dialect = "sqlite3"
	s.dsn = "file:ent?mode=memory&_fk=1"
	s.client = enttest.Open(s.T(), s.dialect, s.dsn)

	s.tokenInfo = &models.Token{
		ClientID:    "1",
		UserID:      "1_1",
		RedirectURI: "http://localhost/",
		Scope:       "all",
	}
}

func (s *CreateTokenTestSuite) TearDownTest() {
	s.client.Close()
}

func (s *CreateTokenTestSuite) TestCodeStore() {
	store, err := NewStoreWithClient(s.ctx, s.client, 0, s.dialect)
	s.NoError(err)

	s.tokenInfo.Code = "11_11_11"
	s.tokenInfo.CodeCreateAt = time.Now()
	s.tokenInfo.CodeExpiresIn = time.Second * 5
	err = store.Create(s.ctx, s.tokenInfo)
	s.NoError(err)

	cInfo, err := store.GetByCode(s.ctx, s.tokenInfo.GetCode())
	s.NoError(err)
	s.Equal(cInfo.GetUserID(), s.tokenInfo.GetUserID())

	err = store.RemoveByCode(s.ctx, s.tokenInfo.GetCode())
	s.NoError(err)

	cInfo, err = store.GetByCode(s.ctx, s.tokenInfo.GetCode())
	s.NoError(err)
	s.Nil(cInfo)
}

func (s *CreateTokenTestSuite) TestAccessStore() {
	store, err := NewStoreWithClient(s.ctx, s.client, 0, s.dialect)
	s.NoError(err)

	s.tokenInfo.Access = "1_1_1"
	s.tokenInfo.AccessCreateAt = time.Now()
	s.tokenInfo.AccessExpiresIn = time.Second * 5
	err = store.Create(s.ctx, s.tokenInfo)
	s.NoError(err)

	aInfo, err := store.GetByAccess(s.ctx, s.tokenInfo.GetAccess())
	s.NoError(err)
	s.Equal(aInfo.GetUserID(), s.tokenInfo.GetUserID())

	err = store.RemoveByAccess(s.ctx, s.tokenInfo.GetAccess())
	s.NoError(err)

	aInfo, err = store.GetByAccess(s.ctx, s.tokenInfo.GetAccess())
	s.NoError(err)
	s.Nil(aInfo)
}

func (s *CreateTokenTestSuite) TestRefreshToken() {
	store, err := NewStoreWithClient(s.ctx, s.client, 0, s.dialect)
	s.NoError(err)

	s.tokenInfo.Access = "1_2_1"
	s.tokenInfo.AccessCreateAt = time.Now()
	s.tokenInfo.AccessExpiresIn = time.Second * 5
	s.tokenInfo.Refresh = "1_2_2"
	s.tokenInfo.RefreshCreateAt = time.Now()
	s.tokenInfo.RefreshExpiresIn = time.Second * 15
	err = store.Create(s.ctx, s.tokenInfo)
	s.NoError(err)

	aInfo, err := store.GetByAccess(s.ctx, s.tokenInfo.GetAccess())
	s.NoError(err)
	s.Equal(aInfo.GetUserID(), s.tokenInfo.GetUserID())

	err = store.RemoveByAccess(s.ctx, s.tokenInfo.GetAccess())
	s.NoError(err)

	aInfo, err = store.GetByAccess(s.ctx, s.tokenInfo.GetAccess())
	s.NoError(err)
	s.Nil(aInfo)

	rInfo, err := store.GetByRefresh(s.ctx, s.tokenInfo.GetRefresh())
	s.NoError(err)
	s.Equal(rInfo.GetUserID(), s.tokenInfo.GetUserID())

	err = store.RemoveByRefresh(s.ctx, s.tokenInfo.GetRefresh())
	s.NoError(err)

	rInfo, err = store.GetByRefresh(s.ctx, s.tokenInfo.GetRefresh())
	s.NoError(err)
	s.Nil(rInfo)
}
