package oauth2ent

import (
	"context"
	"testing"
	"time"

	"github.com/bobobo80/go-oauth2-ent/ent/enttest"
	"github.com/go-oauth2/oauth2/v4/models"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
)

const (
	testDialect = "sqlite3"
	testDSN     = "file:ent?mode=memory&_fk=1"
)

func TestCreateToken(t *testing.T) {
	ctx := context.Background()
	client := enttest.Open(t, testDialect, testDSN)
	defer client.Close()

	store, err := NewStoreWithClient(ctx, client, 0, testDialect)
	assert.NoError(t, err)

	info := &models.Token{
		ClientID:      "1",
		UserID:        "1_1",
		RedirectURI:   "http://localhost/",
		Scope:         "all",
		Code:          "11_11_11",
		CodeCreateAt:  time.Now(),
		CodeExpiresIn: time.Second * 5,
	}
	err = store.Create(ctx, info)
	assert.NoError(t, err)

	cinfo, err := store.GetByCode(ctx, info.Code)
	assert.NoError(t, err)
	assert.Equal(t, cinfo.GetUserID(), info.UserID)

	err = store.RemoveByCode(ctx, info.Code)
	assert.NoError(t, err)

	cinfo, err = store.GetByCode(ctx, info.Code)
	assert.NoError(t, err)
	assert.Nil(t, cinfo)
}
