// Package shieldworkspace provides a set of
package shieldworkspace

import (
	"cmp"
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.inout.gg/foundations/dbsql"
	"go.jetify.com/typeid/v2"

	"go.inout.gg/shield"
	"go.inout.gg/shield/internal/dbsqlc"
	"go.inout.gg/shield/internal/tid"
	"go.inout.gg/shield/shieldsender"
)

var DefaultInvitationExpiryIn = time.Hour * 24 * 7 //nolint:gochecknoglobals

// Workspace represents a workspace.
type Workspace struct {
	Name    string
	ID      typeid.TypeID
	OwnedBy typeid.TypeID
}

// Handler manages the lifecycle of workspaces.
// It provides methods for creating, updating, and deleting workspaces.
// It also handles workspace invitations and member management.
type Handler struct {
	sender shieldsender.Sender
	pool   *pgxpool.Pool
	config *Config
}

type Config struct {
	// Logger is the logger to use for logging.
	Logger *slog.Logger

	// InvitationExpiryIn is the duration after which an invitation expires.
	InvitationExpiryIn time.Duration
}

// NewConfig creates a new configuration for the workspace handler.
func NewConfig(opts ...func(*Config)) *Config {
	//nolint:exhaustruct
	cfg := &Config{}
	for _, opt := range opts {
		opt(cfg)
	}

	cfg.defaults()

	return cfg
}

func (c *Config) defaults() {
	c.InvitationExpiryIn = cmp.Or(
		c.InvitationExpiryIn,
		DefaultInvitationExpiryIn,
	)
	if c.Logger == nil {
		c.Logger = shield.DefaultLogger
	}
}

type WorkspaceInviteMessagePayload struct {
	MemberID    *typeid.TypeID
	Email       string
	WorkspaceID typeid.TypeID
}

// InviteUserToWorkspace invites a user to a workspace by email.
func (h *Handler) InviteUserToWorkspace(
	ctx context.Context,
	workspaceID typeid.TypeID,
	memberEmail string,
) error {
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf(
			"shieldworkspace: failed to begin transaction: %w",
			err,
		)
	}

	defer func() { _ = tx.Rollback(ctx) }()

	invitedUser, err := dbsqlc.New().FindUserByEmail(ctx, tx, memberEmail)
	if err != nil && !dbsql.IsNotFoundError(err) {
		return fmt.Errorf(
			"shieldworkspace: failed to find user by email: %w",
			err,
		)
	}

	var memberID *typeid.TypeID
	if dbsql.IsNotFoundError(err) {
		memberID = &invitedUser.ID
	}

	err = dbsqlc.New().
		InviteUserToWorkspaceByEmail(ctx, tx, dbsqlc.InviteUserToWorkspaceByEmailParams{
			InvitationID: tid.MustWorkspaceMemberInvitationID(),
			WorkspaceID:  workspaceID,
			MemberEmail:  memberEmail,
			ExpiresAt:    time.Now().Add(h.config.InvitationExpiryIn),
		})
	if err != nil {
		return fmt.Errorf(
			"shieldworkspace: failed to invite user to workspace: %w",
			err,
		)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf(
			"shieldworkspace: failed to commit transaction: %w",
			err,
		)
	}

	err = h.sender.Send(ctx, shieldsender.Message{
		Key:   shieldsender.MessageKeyWorkspaceInvite,
		Email: memberEmail,
		Payload: WorkspaceInviteMessagePayload{
			MemberID:    memberID,
			Email:       memberEmail,
			WorkspaceID: workspaceID,
		},
	})
	if err != nil {
		return fmt.Errorf(
			"shieldworkspace: failed to send workspace invite message: %w",
			err,
		)
	}

	return nil
}

// CreateWorkspace creates a new workspace with the given name and owner ID.
// Typically, ownerID is the ID of the user who is creating the workspace.
//
// An ID of the created workspace is returned on success.
func (h *Handler) CreateWorkspace(
	ctx context.Context,
	name string,
	ownerID typeid.TypeID,
) (typeid.TypeID, error) {
	var workspaceID typeid.TypeID

	tx, err := h.pool.Begin(ctx)
	if err != nil {
		return workspaceID, fmt.Errorf(
			"shieldworkspace: failed to begin transaction: %w",
			err,
		)
	}

	defer func() { _ = tx.Rollback(ctx) }()

	w, err := dbsqlc.New().
		CreateWorkspace(ctx, tx, dbsqlc.CreateWorkspaceParams{
			WorkspaceID: workspaceID,
			Name:        name,
			OwnedBy:     ownerID,
		})
	if err != nil {
		return workspaceID, fmt.Errorf(
			"shieldworkspace: failed to create workspace: %w",
			err,
		)
	}

	workspaceID = w.ID

	return workspaceID, nil
}

// FindWorkspace retrieves a workspace by its ID.
func FindWorkspace(
	ctx context.Context,
	workspaceID typeid.TypeID,
	db dbsqlc.DBTX,
) (*Workspace, error) {
	w, err := dbsqlc.New().FindWorkspaceByID(ctx, db, workspaceID)
	if err != nil {
		return nil, fmt.Errorf(
			"shieldworkspace: failed to find workspace by ID: %w",
			err,
		)
	}

	return &Workspace{
		ID:      w.ID,
		Name:    w.Name,
		OwnedBy: w.OwnedBy,
	}, nil
}
