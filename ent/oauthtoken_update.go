// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"
	"time"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/bobobo80/go-oauth2-ent/ent/oauthtoken"
	"github.com/bobobo80/go-oauth2-ent/ent/predicate"
)

// OAuthTokenUpdate is the builder for updating OAuthToken entities.
type OAuthTokenUpdate struct {
	config
	hooks    []Hook
	mutation *OAuthTokenMutation
}

// Where appends a list predicates to the OAuthTokenUpdate builder.
func (otu *OAuthTokenUpdate) Where(ps ...predicate.OAuthToken) *OAuthTokenUpdate {
	otu.mutation.Where(ps...)
	return otu
}

// SetExpiredAt sets the "expired_at" field.
func (otu *OAuthTokenUpdate) SetExpiredAt(t time.Time) *OAuthTokenUpdate {
	otu.mutation.SetExpiredAt(t)
	return otu
}

// SetNillableExpiredAt sets the "expired_at" field if the given value is not nil.
func (otu *OAuthTokenUpdate) SetNillableExpiredAt(t *time.Time) *OAuthTokenUpdate {
	if t != nil {
		otu.SetExpiredAt(*t)
	}
	return otu
}

// SetCode sets the "code" field.
func (otu *OAuthTokenUpdate) SetCode(s string) *OAuthTokenUpdate {
	otu.mutation.SetCode(s)
	return otu
}

// SetNillableCode sets the "code" field if the given value is not nil.
func (otu *OAuthTokenUpdate) SetNillableCode(s *string) *OAuthTokenUpdate {
	if s != nil {
		otu.SetCode(*s)
	}
	return otu
}

// SetAccess sets the "access" field.
func (otu *OAuthTokenUpdate) SetAccess(s string) *OAuthTokenUpdate {
	otu.mutation.SetAccess(s)
	return otu
}

// SetNillableAccess sets the "access" field if the given value is not nil.
func (otu *OAuthTokenUpdate) SetNillableAccess(s *string) *OAuthTokenUpdate {
	if s != nil {
		otu.SetAccess(*s)
	}
	return otu
}

// SetRefresh sets the "refresh" field.
func (otu *OAuthTokenUpdate) SetRefresh(s string) *OAuthTokenUpdate {
	otu.mutation.SetRefresh(s)
	return otu
}

// SetNillableRefresh sets the "refresh" field if the given value is not nil.
func (otu *OAuthTokenUpdate) SetNillableRefresh(s *string) *OAuthTokenUpdate {
	if s != nil {
		otu.SetRefresh(*s)
	}
	return otu
}

// SetData sets the "data" field.
func (otu *OAuthTokenUpdate) SetData(s string) *OAuthTokenUpdate {
	otu.mutation.SetData(s)
	return otu
}

// Mutation returns the OAuthTokenMutation object of the builder.
func (otu *OAuthTokenUpdate) Mutation() *OAuthTokenMutation {
	return otu.mutation
}

// Save executes the query and returns the number of nodes affected by the update operation.
func (otu *OAuthTokenUpdate) Save(ctx context.Context) (int, error) {
	return withHooks[int, OAuthTokenMutation](ctx, otu.sqlSave, otu.mutation, otu.hooks)
}

// SaveX is like Save, but panics if an error occurs.
func (otu *OAuthTokenUpdate) SaveX(ctx context.Context) int {
	affected, err := otu.Save(ctx)
	if err != nil {
		panic(err)
	}
	return affected
}

// Exec executes the query.
func (otu *OAuthTokenUpdate) Exec(ctx context.Context) error {
	_, err := otu.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (otu *OAuthTokenUpdate) ExecX(ctx context.Context) {
	if err := otu.Exec(ctx); err != nil {
		panic(err)
	}
}

// check runs all checks and user-defined validators on the builder.
func (otu *OAuthTokenUpdate) check() error {
	if v, ok := otu.mutation.Code(); ok {
		if err := oauthtoken.CodeValidator(v); err != nil {
			return &ValidationError{Name: "code", err: fmt.Errorf(`ent: validator failed for field "OAuthToken.code": %w`, err)}
		}
	}
	if v, ok := otu.mutation.Access(); ok {
		if err := oauthtoken.AccessValidator(v); err != nil {
			return &ValidationError{Name: "access", err: fmt.Errorf(`ent: validator failed for field "OAuthToken.access": %w`, err)}
		}
	}
	if v, ok := otu.mutation.Refresh(); ok {
		if err := oauthtoken.RefreshValidator(v); err != nil {
			return &ValidationError{Name: "refresh", err: fmt.Errorf(`ent: validator failed for field "OAuthToken.refresh": %w`, err)}
		}
	}
	if v, ok := otu.mutation.Data(); ok {
		if err := oauthtoken.DataValidator(v); err != nil {
			return &ValidationError{Name: "data", err: fmt.Errorf(`ent: validator failed for field "OAuthToken.data": %w`, err)}
		}
	}
	return nil
}

func (otu *OAuthTokenUpdate) sqlSave(ctx context.Context) (n int, err error) {
	if err := otu.check(); err != nil {
		return n, err
	}
	_spec := sqlgraph.NewUpdateSpec(oauthtoken.Table, oauthtoken.Columns, sqlgraph.NewFieldSpec(oauthtoken.FieldID, field.TypeInt))
	if ps := otu.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := otu.mutation.ExpiredAt(); ok {
		_spec.SetField(oauthtoken.FieldExpiredAt, field.TypeTime, value)
	}
	if value, ok := otu.mutation.Code(); ok {
		_spec.SetField(oauthtoken.FieldCode, field.TypeString, value)
	}
	if value, ok := otu.mutation.Access(); ok {
		_spec.SetField(oauthtoken.FieldAccess, field.TypeString, value)
	}
	if value, ok := otu.mutation.Refresh(); ok {
		_spec.SetField(oauthtoken.FieldRefresh, field.TypeString, value)
	}
	if value, ok := otu.mutation.Data(); ok {
		_spec.SetField(oauthtoken.FieldData, field.TypeString, value)
	}
	if n, err = sqlgraph.UpdateNodes(ctx, otu.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{oauthtoken.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return 0, err
	}
	otu.mutation.done = true
	return n, nil
}

// OAuthTokenUpdateOne is the builder for updating a single OAuthToken entity.
type OAuthTokenUpdateOne struct {
	config
	fields   []string
	hooks    []Hook
	mutation *OAuthTokenMutation
}

// SetExpiredAt sets the "expired_at" field.
func (otuo *OAuthTokenUpdateOne) SetExpiredAt(t time.Time) *OAuthTokenUpdateOne {
	otuo.mutation.SetExpiredAt(t)
	return otuo
}

// SetNillableExpiredAt sets the "expired_at" field if the given value is not nil.
func (otuo *OAuthTokenUpdateOne) SetNillableExpiredAt(t *time.Time) *OAuthTokenUpdateOne {
	if t != nil {
		otuo.SetExpiredAt(*t)
	}
	return otuo
}

// SetCode sets the "code" field.
func (otuo *OAuthTokenUpdateOne) SetCode(s string) *OAuthTokenUpdateOne {
	otuo.mutation.SetCode(s)
	return otuo
}

// SetNillableCode sets the "code" field if the given value is not nil.
func (otuo *OAuthTokenUpdateOne) SetNillableCode(s *string) *OAuthTokenUpdateOne {
	if s != nil {
		otuo.SetCode(*s)
	}
	return otuo
}

// SetAccess sets the "access" field.
func (otuo *OAuthTokenUpdateOne) SetAccess(s string) *OAuthTokenUpdateOne {
	otuo.mutation.SetAccess(s)
	return otuo
}

// SetNillableAccess sets the "access" field if the given value is not nil.
func (otuo *OAuthTokenUpdateOne) SetNillableAccess(s *string) *OAuthTokenUpdateOne {
	if s != nil {
		otuo.SetAccess(*s)
	}
	return otuo
}

// SetRefresh sets the "refresh" field.
func (otuo *OAuthTokenUpdateOne) SetRefresh(s string) *OAuthTokenUpdateOne {
	otuo.mutation.SetRefresh(s)
	return otuo
}

// SetNillableRefresh sets the "refresh" field if the given value is not nil.
func (otuo *OAuthTokenUpdateOne) SetNillableRefresh(s *string) *OAuthTokenUpdateOne {
	if s != nil {
		otuo.SetRefresh(*s)
	}
	return otuo
}

// SetData sets the "data" field.
func (otuo *OAuthTokenUpdateOne) SetData(s string) *OAuthTokenUpdateOne {
	otuo.mutation.SetData(s)
	return otuo
}

// Mutation returns the OAuthTokenMutation object of the builder.
func (otuo *OAuthTokenUpdateOne) Mutation() *OAuthTokenMutation {
	return otuo.mutation
}

// Where appends a list predicates to the OAuthTokenUpdate builder.
func (otuo *OAuthTokenUpdateOne) Where(ps ...predicate.OAuthToken) *OAuthTokenUpdateOne {
	otuo.mutation.Where(ps...)
	return otuo
}

// Select allows selecting one or more fields (columns) of the returned entity.
// The default is selecting all fields defined in the entity schema.
func (otuo *OAuthTokenUpdateOne) Select(field string, fields ...string) *OAuthTokenUpdateOne {
	otuo.fields = append([]string{field}, fields...)
	return otuo
}

// Save executes the query and returns the updated OAuthToken entity.
func (otuo *OAuthTokenUpdateOne) Save(ctx context.Context) (*OAuthToken, error) {
	return withHooks[*OAuthToken, OAuthTokenMutation](ctx, otuo.sqlSave, otuo.mutation, otuo.hooks)
}

// SaveX is like Save, but panics if an error occurs.
func (otuo *OAuthTokenUpdateOne) SaveX(ctx context.Context) *OAuthToken {
	node, err := otuo.Save(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// Exec executes the query on the entity.
func (otuo *OAuthTokenUpdateOne) Exec(ctx context.Context) error {
	_, err := otuo.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (otuo *OAuthTokenUpdateOne) ExecX(ctx context.Context) {
	if err := otuo.Exec(ctx); err != nil {
		panic(err)
	}
}

// check runs all checks and user-defined validators on the builder.
func (otuo *OAuthTokenUpdateOne) check() error {
	if v, ok := otuo.mutation.Code(); ok {
		if err := oauthtoken.CodeValidator(v); err != nil {
			return &ValidationError{Name: "code", err: fmt.Errorf(`ent: validator failed for field "OAuthToken.code": %w`, err)}
		}
	}
	if v, ok := otuo.mutation.Access(); ok {
		if err := oauthtoken.AccessValidator(v); err != nil {
			return &ValidationError{Name: "access", err: fmt.Errorf(`ent: validator failed for field "OAuthToken.access": %w`, err)}
		}
	}
	if v, ok := otuo.mutation.Refresh(); ok {
		if err := oauthtoken.RefreshValidator(v); err != nil {
			return &ValidationError{Name: "refresh", err: fmt.Errorf(`ent: validator failed for field "OAuthToken.refresh": %w`, err)}
		}
	}
	if v, ok := otuo.mutation.Data(); ok {
		if err := oauthtoken.DataValidator(v); err != nil {
			return &ValidationError{Name: "data", err: fmt.Errorf(`ent: validator failed for field "OAuthToken.data": %w`, err)}
		}
	}
	return nil
}

func (otuo *OAuthTokenUpdateOne) sqlSave(ctx context.Context) (_node *OAuthToken, err error) {
	if err := otuo.check(); err != nil {
		return _node, err
	}
	_spec := sqlgraph.NewUpdateSpec(oauthtoken.Table, oauthtoken.Columns, sqlgraph.NewFieldSpec(oauthtoken.FieldID, field.TypeInt))
	id, ok := otuo.mutation.ID()
	if !ok {
		return nil, &ValidationError{Name: "id", err: errors.New(`ent: missing "OAuthToken.id" for update`)}
	}
	_spec.Node.ID.Value = id
	if fields := otuo.fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, oauthtoken.FieldID)
		for _, f := range fields {
			if !oauthtoken.ValidColumn(f) {
				return nil, &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
			}
			if f != oauthtoken.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, f)
			}
		}
	}
	if ps := otuo.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := otuo.mutation.ExpiredAt(); ok {
		_spec.SetField(oauthtoken.FieldExpiredAt, field.TypeTime, value)
	}
	if value, ok := otuo.mutation.Code(); ok {
		_spec.SetField(oauthtoken.FieldCode, field.TypeString, value)
	}
	if value, ok := otuo.mutation.Access(); ok {
		_spec.SetField(oauthtoken.FieldAccess, field.TypeString, value)
	}
	if value, ok := otuo.mutation.Refresh(); ok {
		_spec.SetField(oauthtoken.FieldRefresh, field.TypeString, value)
	}
	if value, ok := otuo.mutation.Data(); ok {
		_spec.SetField(oauthtoken.FieldData, field.TypeString, value)
	}
	_node = &OAuthToken{config: otuo.config}
	_spec.Assign = _node.assignValues
	_spec.ScanValues = _node.scanValues
	if err = sqlgraph.UpdateNode(ctx, otuo.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{oauthtoken.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	otuo.mutation.done = true
	return _node, nil
}