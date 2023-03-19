// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"fmt"
	"math"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/bobobo80/go-oauth2-ent/ent/oauthtoken"
	"github.com/bobobo80/go-oauth2-ent/ent/predicate"
)

// OAuthTokenQuery is the builder for querying OAuthToken entities.
type OAuthTokenQuery struct {
	config
	ctx        *QueryContext
	order      []OrderFunc
	inters     []Interceptor
	predicates []predicate.OAuthToken
	// intermediate query (i.e. traversal path).
	sql  *sql.Selector
	path func(context.Context) (*sql.Selector, error)
}

// Where adds a new predicate for the OAuthTokenQuery builder.
func (otq *OAuthTokenQuery) Where(ps ...predicate.OAuthToken) *OAuthTokenQuery {
	otq.predicates = append(otq.predicates, ps...)
	return otq
}

// Limit the number of records to be returned by this query.
func (otq *OAuthTokenQuery) Limit(limit int) *OAuthTokenQuery {
	otq.ctx.Limit = &limit
	return otq
}

// Offset to start from.
func (otq *OAuthTokenQuery) Offset(offset int) *OAuthTokenQuery {
	otq.ctx.Offset = &offset
	return otq
}

// Unique configures the query builder to filter duplicate records on query.
// By default, unique is set to true, and can be disabled using this method.
func (otq *OAuthTokenQuery) Unique(unique bool) *OAuthTokenQuery {
	otq.ctx.Unique = &unique
	return otq
}

// Order specifies how the records should be ordered.
func (otq *OAuthTokenQuery) Order(o ...OrderFunc) *OAuthTokenQuery {
	otq.order = append(otq.order, o...)
	return otq
}

// First returns the first OAuthToken entity from the query.
// Returns a *NotFoundError when no OAuthToken was found.
func (otq *OAuthTokenQuery) First(ctx context.Context) (*OAuthToken, error) {
	nodes, err := otq.Limit(1).All(setContextOp(ctx, otq.ctx, "First"))
	if err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nil, &NotFoundError{oauthtoken.Label}
	}
	return nodes[0], nil
}

// FirstX is like First, but panics if an error occurs.
func (otq *OAuthTokenQuery) FirstX(ctx context.Context) *OAuthToken {
	node, err := otq.First(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return node
}

// FirstID returns the first OAuthToken ID from the query.
// Returns a *NotFoundError when no OAuthToken ID was found.
func (otq *OAuthTokenQuery) FirstID(ctx context.Context) (id int, err error) {
	var ids []int
	if ids, err = otq.Limit(1).IDs(setContextOp(ctx, otq.ctx, "FirstID")); err != nil {
		return
	}
	if len(ids) == 0 {
		err = &NotFoundError{oauthtoken.Label}
		return
	}
	return ids[0], nil
}

// FirstIDX is like FirstID, but panics if an error occurs.
func (otq *OAuthTokenQuery) FirstIDX(ctx context.Context) int {
	id, err := otq.FirstID(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return id
}

// Only returns a single OAuthToken entity found by the query, ensuring it only returns one.
// Returns a *NotSingularError when more than one OAuthToken entity is found.
// Returns a *NotFoundError when no OAuthToken entities are found.
func (otq *OAuthTokenQuery) Only(ctx context.Context) (*OAuthToken, error) {
	nodes, err := otq.Limit(2).All(setContextOp(ctx, otq.ctx, "Only"))
	if err != nil {
		return nil, err
	}
	switch len(nodes) {
	case 1:
		return nodes[0], nil
	case 0:
		return nil, &NotFoundError{oauthtoken.Label}
	default:
		return nil, &NotSingularError{oauthtoken.Label}
	}
}

// OnlyX is like Only, but panics if an error occurs.
func (otq *OAuthTokenQuery) OnlyX(ctx context.Context) *OAuthToken {
	node, err := otq.Only(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// OnlyID is like Only, but returns the only OAuthToken ID in the query.
// Returns a *NotSingularError when more than one OAuthToken ID is found.
// Returns a *NotFoundError when no entities are found.
func (otq *OAuthTokenQuery) OnlyID(ctx context.Context) (id int, err error) {
	var ids []int
	if ids, err = otq.Limit(2).IDs(setContextOp(ctx, otq.ctx, "OnlyID")); err != nil {
		return
	}
	switch len(ids) {
	case 1:
		id = ids[0]
	case 0:
		err = &NotFoundError{oauthtoken.Label}
	default:
		err = &NotSingularError{oauthtoken.Label}
	}
	return
}

// OnlyIDX is like OnlyID, but panics if an error occurs.
func (otq *OAuthTokenQuery) OnlyIDX(ctx context.Context) int {
	id, err := otq.OnlyID(ctx)
	if err != nil {
		panic(err)
	}
	return id
}

// All executes the query and returns a list of OAuthTokens.
func (otq *OAuthTokenQuery) All(ctx context.Context) ([]*OAuthToken, error) {
	ctx = setContextOp(ctx, otq.ctx, "All")
	if err := otq.prepareQuery(ctx); err != nil {
		return nil, err
	}
	qr := querierAll[[]*OAuthToken, *OAuthTokenQuery]()
	return withInterceptors[[]*OAuthToken](ctx, otq, qr, otq.inters)
}

// AllX is like All, but panics if an error occurs.
func (otq *OAuthTokenQuery) AllX(ctx context.Context) []*OAuthToken {
	nodes, err := otq.All(ctx)
	if err != nil {
		panic(err)
	}
	return nodes
}

// IDs executes the query and returns a list of OAuthToken IDs.
func (otq *OAuthTokenQuery) IDs(ctx context.Context) (ids []int, err error) {
	if otq.ctx.Unique == nil && otq.path != nil {
		otq.Unique(true)
	}
	ctx = setContextOp(ctx, otq.ctx, "IDs")
	if err = otq.Select(oauthtoken.FieldID).Scan(ctx, &ids); err != nil {
		return nil, err
	}
	return ids, nil
}

// IDsX is like IDs, but panics if an error occurs.
func (otq *OAuthTokenQuery) IDsX(ctx context.Context) []int {
	ids, err := otq.IDs(ctx)
	if err != nil {
		panic(err)
	}
	return ids
}

// Count returns the count of the given query.
func (otq *OAuthTokenQuery) Count(ctx context.Context) (int, error) {
	ctx = setContextOp(ctx, otq.ctx, "Count")
	if err := otq.prepareQuery(ctx); err != nil {
		return 0, err
	}
	return withInterceptors[int](ctx, otq, querierCount[*OAuthTokenQuery](), otq.inters)
}

// CountX is like Count, but panics if an error occurs.
func (otq *OAuthTokenQuery) CountX(ctx context.Context) int {
	count, err := otq.Count(ctx)
	if err != nil {
		panic(err)
	}
	return count
}

// Exist returns true if the query has elements in the graph.
func (otq *OAuthTokenQuery) Exist(ctx context.Context) (bool, error) {
	ctx = setContextOp(ctx, otq.ctx, "Exist")
	switch _, err := otq.FirstID(ctx); {
	case IsNotFound(err):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("ent: check existence: %w", err)
	default:
		return true, nil
	}
}

// ExistX is like Exist, but panics if an error occurs.
func (otq *OAuthTokenQuery) ExistX(ctx context.Context) bool {
	exist, err := otq.Exist(ctx)
	if err != nil {
		panic(err)
	}
	return exist
}

// Clone returns a duplicate of the OAuthTokenQuery builder, including all associated steps. It can be
// used to prepare common query builders and use them differently after the clone is made.
func (otq *OAuthTokenQuery) Clone() *OAuthTokenQuery {
	if otq == nil {
		return nil
	}
	return &OAuthTokenQuery{
		config:     otq.config,
		ctx:        otq.ctx.Clone(),
		order:      append([]OrderFunc{}, otq.order...),
		inters:     append([]Interceptor{}, otq.inters...),
		predicates: append([]predicate.OAuthToken{}, otq.predicates...),
		// clone intermediate query.
		sql:  otq.sql.Clone(),
		path: otq.path,
	}
}

// GroupBy is used to group vertices by one or more fields/columns.
// It is often used with aggregate functions, like: count, max, mean, min, sum.
//
// Example:
//
//	var v []struct {
//		ExpiredAt time.Time `json:"expired_at,omitempty"`
//		Count int `json:"count,omitempty"`
//	}
//
//	client.OAuthToken.Query().
//		GroupBy(oauthtoken.FieldExpiredAt).
//		Aggregate(ent.Count()).
//		Scan(ctx, &v)
func (otq *OAuthTokenQuery) GroupBy(field string, fields ...string) *OAuthTokenGroupBy {
	otq.ctx.Fields = append([]string{field}, fields...)
	grbuild := &OAuthTokenGroupBy{build: otq}
	grbuild.flds = &otq.ctx.Fields
	grbuild.label = oauthtoken.Label
	grbuild.scan = grbuild.Scan
	return grbuild
}

// Select allows the selection one or more fields/columns for the given query,
// instead of selecting all fields in the entity.
//
// Example:
//
//	var v []struct {
//		ExpiredAt time.Time `json:"expired_at,omitempty"`
//	}
//
//	client.OAuthToken.Query().
//		Select(oauthtoken.FieldExpiredAt).
//		Scan(ctx, &v)
func (otq *OAuthTokenQuery) Select(fields ...string) *OAuthTokenSelect {
	otq.ctx.Fields = append(otq.ctx.Fields, fields...)
	sbuild := &OAuthTokenSelect{OAuthTokenQuery: otq}
	sbuild.label = oauthtoken.Label
	sbuild.flds, sbuild.scan = &otq.ctx.Fields, sbuild.Scan
	return sbuild
}

// Aggregate returns a OAuthTokenSelect configured with the given aggregations.
func (otq *OAuthTokenQuery) Aggregate(fns ...AggregateFunc) *OAuthTokenSelect {
	return otq.Select().Aggregate(fns...)
}

func (otq *OAuthTokenQuery) prepareQuery(ctx context.Context) error {
	for _, inter := range otq.inters {
		if inter == nil {
			return fmt.Errorf("ent: uninitialized interceptor (forgotten import ent/runtime?)")
		}
		if trv, ok := inter.(Traverser); ok {
			if err := trv.Traverse(ctx, otq); err != nil {
				return err
			}
		}
	}
	for _, f := range otq.ctx.Fields {
		if !oauthtoken.ValidColumn(f) {
			return &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
		}
	}
	if otq.path != nil {
		prev, err := otq.path(ctx)
		if err != nil {
			return err
		}
		otq.sql = prev
	}
	return nil
}

func (otq *OAuthTokenQuery) sqlAll(ctx context.Context, hooks ...queryHook) ([]*OAuthToken, error) {
	var (
		nodes = []*OAuthToken{}
		_spec = otq.querySpec()
	)
	_spec.ScanValues = func(columns []string) ([]any, error) {
		return (*OAuthToken).scanValues(nil, columns)
	}
	_spec.Assign = func(columns []string, values []any) error {
		node := &OAuthToken{config: otq.config}
		nodes = append(nodes, node)
		return node.assignValues(columns, values)
	}
	for i := range hooks {
		hooks[i](ctx, _spec)
	}
	if err := sqlgraph.QueryNodes(ctx, otq.driver, _spec); err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nodes, nil
	}
	return nodes, nil
}

func (otq *OAuthTokenQuery) sqlCount(ctx context.Context) (int, error) {
	_spec := otq.querySpec()
	_spec.Node.Columns = otq.ctx.Fields
	if len(otq.ctx.Fields) > 0 {
		_spec.Unique = otq.ctx.Unique != nil && *otq.ctx.Unique
	}
	return sqlgraph.CountNodes(ctx, otq.driver, _spec)
}

func (otq *OAuthTokenQuery) querySpec() *sqlgraph.QuerySpec {
	_spec := sqlgraph.NewQuerySpec(oauthtoken.Table, oauthtoken.Columns, sqlgraph.NewFieldSpec(oauthtoken.FieldID, field.TypeInt))
	_spec.From = otq.sql
	if unique := otq.ctx.Unique; unique != nil {
		_spec.Unique = *unique
	} else if otq.path != nil {
		_spec.Unique = true
	}
	if fields := otq.ctx.Fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, oauthtoken.FieldID)
		for i := range fields {
			if fields[i] != oauthtoken.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, fields[i])
			}
		}
	}
	if ps := otq.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if limit := otq.ctx.Limit; limit != nil {
		_spec.Limit = *limit
	}
	if offset := otq.ctx.Offset; offset != nil {
		_spec.Offset = *offset
	}
	if ps := otq.order; len(ps) > 0 {
		_spec.Order = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	return _spec
}

func (otq *OAuthTokenQuery) sqlQuery(ctx context.Context) *sql.Selector {
	builder := sql.Dialect(otq.driver.Dialect())
	t1 := builder.Table(oauthtoken.Table)
	columns := otq.ctx.Fields
	if len(columns) == 0 {
		columns = oauthtoken.Columns
	}
	selector := builder.Select(t1.Columns(columns...)...).From(t1)
	if otq.sql != nil {
		selector = otq.sql
		selector.Select(selector.Columns(columns...)...)
	}
	if otq.ctx.Unique != nil && *otq.ctx.Unique {
		selector.Distinct()
	}
	for _, p := range otq.predicates {
		p(selector)
	}
	for _, p := range otq.order {
		p(selector)
	}
	if offset := otq.ctx.Offset; offset != nil {
		// limit is mandatory for offset clause. We start
		// with default value, and override it below if needed.
		selector.Offset(*offset).Limit(math.MaxInt32)
	}
	if limit := otq.ctx.Limit; limit != nil {
		selector.Limit(*limit)
	}
	return selector
}

// OAuthTokenGroupBy is the group-by builder for OAuthToken entities.
type OAuthTokenGroupBy struct {
	selector
	build *OAuthTokenQuery
}

// Aggregate adds the given aggregation functions to the group-by query.
func (otgb *OAuthTokenGroupBy) Aggregate(fns ...AggregateFunc) *OAuthTokenGroupBy {
	otgb.fns = append(otgb.fns, fns...)
	return otgb
}

// Scan applies the selector query and scans the result into the given value.
func (otgb *OAuthTokenGroupBy) Scan(ctx context.Context, v any) error {
	ctx = setContextOp(ctx, otgb.build.ctx, "GroupBy")
	if err := otgb.build.prepareQuery(ctx); err != nil {
		return err
	}
	return scanWithInterceptors[*OAuthTokenQuery, *OAuthTokenGroupBy](ctx, otgb.build, otgb, otgb.build.inters, v)
}

func (otgb *OAuthTokenGroupBy) sqlScan(ctx context.Context, root *OAuthTokenQuery, v any) error {
	selector := root.sqlQuery(ctx).Select()
	aggregation := make([]string, 0, len(otgb.fns))
	for _, fn := range otgb.fns {
		aggregation = append(aggregation, fn(selector))
	}
	if len(selector.SelectedColumns()) == 0 {
		columns := make([]string, 0, len(*otgb.flds)+len(otgb.fns))
		for _, f := range *otgb.flds {
			columns = append(columns, selector.C(f))
		}
		columns = append(columns, aggregation...)
		selector.Select(columns...)
	}
	selector.GroupBy(selector.Columns(*otgb.flds...)...)
	if err := selector.Err(); err != nil {
		return err
	}
	rows := &sql.Rows{}
	query, args := selector.Query()
	if err := otgb.build.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}

// OAuthTokenSelect is the builder for selecting fields of OAuthToken entities.
type OAuthTokenSelect struct {
	*OAuthTokenQuery
	selector
}

// Aggregate adds the given aggregation functions to the selector query.
func (ots *OAuthTokenSelect) Aggregate(fns ...AggregateFunc) *OAuthTokenSelect {
	ots.fns = append(ots.fns, fns...)
	return ots
}

// Scan applies the selector query and scans the result into the given value.
func (ots *OAuthTokenSelect) Scan(ctx context.Context, v any) error {
	ctx = setContextOp(ctx, ots.ctx, "Select")
	if err := ots.prepareQuery(ctx); err != nil {
		return err
	}
	return scanWithInterceptors[*OAuthTokenQuery, *OAuthTokenSelect](ctx, ots.OAuthTokenQuery, ots, ots.inters, v)
}

func (ots *OAuthTokenSelect) sqlScan(ctx context.Context, root *OAuthTokenQuery, v any) error {
	selector := root.sqlQuery(ctx)
	aggregation := make([]string, 0, len(ots.fns))
	for _, fn := range ots.fns {
		aggregation = append(aggregation, fn(selector))
	}
	switch n := len(*ots.selector.flds); {
	case n == 0 && len(aggregation) > 0:
		selector.Select(aggregation...)
	case n != 0 && len(aggregation) > 0:
		selector.AppendSelect(aggregation...)
	}
	rows := &sql.Rows{}
	query, args := selector.Query()
	if err := ots.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}
