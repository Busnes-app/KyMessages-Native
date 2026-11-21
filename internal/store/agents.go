package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

type agentStore struct {
	store *SQLStore
}

const agentColumns = "id, user_id, username, display_name, owner_user_id, token_hash, token_state, last_used_at, created_by, created_at"

func scanAgent(row interface{ Scan(...any) error }) (*Agent, error) {
	var a Agent
	var lastUsed sql.NullTime
	err := row.Scan(&a.ID, &a.UserID, &a.Username, &a.DisplayName, &a.OwnerUserID, &a.TokenHash, &a.TokenState, &lastUsed, &a.CreatedBy, &a.CreatedAt)
	if err != nil {
		return nil, err
	}
	if lastUsed.Valid {
		t := lastUsed.Time.UTC()
		a.LastUsedAt = &t
	}
	return &a, nil
}

func validAgentToken(tokenHash, state string) error {
	switch {
	case state == AgentTokenActive && tokenHash != "":
	case (state == AgentTokenRevoked || state == AgentTokenExpired) && tokenHash == "":
	default:
		return fmt.Errorf("agent token state %q with token hash length %d", state, len(tokenHash))
	}
	return nil
}

func (s *agentStore) CreateAgent(ctx context.Context, a *Agent) error {
	if err := validAgentToken(a.TokenHash, a.TokenState); err != nil {
		return err
	}
	if a.CreatedAt.IsZero() {
		a.CreatedAt = time.Now().UTC()
	}
	var lastUsed any
	if a.LastUsedAt != nil {
		lastUsed = a.LastUsedAt.UTC()
	}
	q := s.store.rebind(`INSERT INTO agents (` + agentColumns + `) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	_, err := s.store.db.ExecContext(ctx, q, a.ID, a.UserID, a.Username, a.DisplayName, a.OwnerUserID, a.TokenHash, a.TokenState, lastUsed, a.CreatedBy, a.CreatedAt)
	return uniqueError(err)
}

func (s *agentStore) GetAgent(ctx context.Context, id string) (*Agent, error) {
	a, err := scanAgent(s.store.db.QueryRowContext(ctx, s.store.rebind(`SELECT `+agentColumns+` FROM agents WHERE id = ?`), id))
	if errorsIs(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return a, nil
}

func (s *agentStore) GetAgentByTokenHash(ctx context.Context, tokenHash string) (*Agent, error) {
	if tokenHash == "" {
		return nil, ErrNotFound
	}
	q := s.store.rebind(`SELECT ` + agentColumns + ` FROM agents WHERE token_hash = ? AND token_state = ?`)
	a, err := scanAgent(s.store.db.QueryRowContext(ctx, q, tokenHash, AgentTokenActive))
	if errorsIs(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return a, nil
}

func (s *agentStore) ListAgents(ctx context.Context) ([]*Agent, error) {
	rows, err := s.store.db.QueryContext(ctx, `SELECT `+agentColumns+` FROM agents ORDER BY created_at, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Agent
	for rows.Next() {
		a, err := scanAgent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *agentStore) ListAgentsByOwner(ctx context.Context, ownerUserID string) ([]*Agent, error) {
	rows, err := s.store.db.QueryContext(ctx, s.store.rebind(`SELECT `+agentColumns+` FROM agents WHERE owner_user_id = ? ORDER BY created_at, id`), ownerUserID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Agent
	for rows.Next() {
		a, err := scanAgent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *agentStore) SetAgentToken(ctx context.Context, id, fromTokenHash, newTokenHash, state string) error {
	if err := validAgentToken(newTokenHash, state); err != nil {
		return err
	}
	q := s.store.rebind(`UPDATE agents SET token_hash = ?, token_state = ? WHERE id = ? AND token_hash = ?`)
	res, err := s.store.db.ExecContext(ctx, q, newTokenHash, state, id, fromTokenHash)
	return oneRow(uniqueResult(res, err))
}

func (s *agentStore) TouchAgentLastUsed(ctx context.Context, id string, at time.Time) error {
	q := s.store.rebind(`UPDATE agents SET last_used_at = ? WHERE id = ?`)
	_, err := s.store.db.ExecContext(ctx, q, at.UTC(), id)
	return err
}

func uniqueResult(res sql.Result, err error) (sql.Result, error) { return res, uniqueError(err) }

func (s *agentStore) DeleteAgent(ctx context.Context, id string) error {
	res, err := s.store.db.ExecContext(ctx, s.store.rebind(`DELETE FROM agents WHERE id = ?`), id)
	return oneRow(res, err)
}
