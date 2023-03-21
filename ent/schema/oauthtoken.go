package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// OAuthToken holds the schema definition for the OAuthToken entity.
type OAuthToken struct {
	ent.Schema
}

// Fields of the OAuthToken.
func (OAuthToken) Fields() []ent.Field {
	return []ent.Field{
		field.Time("expired_at").Default(time.Now),
		field.String("code").MaxLen(255).Default(""),
		field.String("access").MaxLen(255).Default(""),
		field.String("refresh").MaxLen(255).Default(""),
		field.String("data").MaxLen(2048),
	}
}

// Edges of the OAuthToken.
func (OAuthToken) Edges() []ent.Edge {
	return nil
}

func (OAuthToken) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("expired_at"),
		index.Fields("code"),
		index.Fields("access"),
		index.Fields("refresh"),
	}
}
