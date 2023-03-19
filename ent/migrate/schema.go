// Code generated by ent, DO NOT EDIT.

package migrate

import (
	"entgo.io/ent/dialect/sql/schema"
	"entgo.io/ent/schema/field"
)

var (
	// OauthTokensColumns holds the columns for the "oauth_tokens" table.
	OauthTokensColumns = []*schema.Column{
		{Name: "id", Type: field.TypeInt, Increment: true},
		{Name: "expired_at", Type: field.TypeTime},
		{Name: "code", Type: field.TypeString, Size: 255, Default: ""},
		{Name: "access", Type: field.TypeString, Size: 255, Default: ""},
		{Name: "refresh", Type: field.TypeString, Size: 255, Default: ""},
		{Name: "data", Type: field.TypeString, Size: 2048},
	}
	// OauthTokensTable holds the schema information for the "oauth_tokens" table.
	OauthTokensTable = &schema.Table{
		Name:       "oauth_tokens",
		Columns:    OauthTokensColumns,
		PrimaryKey: []*schema.Column{OauthTokensColumns[0]},
		Indexes: []*schema.Index{
			{
				Name:    "oauthtoken_expired_at",
				Unique:  false,
				Columns: []*schema.Column{OauthTokensColumns[1]},
			},
			{
				Name:    "oauthtoken_code",
				Unique:  false,
				Columns: []*schema.Column{OauthTokensColumns[2]},
			},
			{
				Name:    "oauthtoken_access",
				Unique:  false,
				Columns: []*schema.Column{OauthTokensColumns[3]},
			},
			{
				Name:    "oauthtoken_refresh",
				Unique:  false,
				Columns: []*schema.Column{OauthTokensColumns[4]},
			},
		},
	}
	// Tables holds all the tables in the schema.
	Tables = []*schema.Table{
		OauthTokensTable,
	}
)

func init() {
}