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

	"go.inout.gg/shield"
	"go.inout.gg/shield/internal/dbsqlc"
	"go.inout.gg/shield/shieldsender"
)

var DefaultInvitationExpiryIn = time.Hour * 24 * 7 //nolint:gochecknoglobals

// Workspace represents a workspace.
type Workspace struct {
	Name    string
	ID      int64
	OwnedBy int64
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
	MemberID    *int64
	Email       string
	WorkspaceID int64
}

// InviteUserToWorkspace invites a user to a workspace by email.
func (h *Handler) InviteUserToWorkspace(
	ctx context.Context,
	workspaceID int64,
	teamID int64,
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

	var memberID *int64
	if !dbsql.IsNotFoundError(err) {
		memberID = &invitedUser.ID
	}

	err = dbsqlc.New().
		InviteUserToWorkspaceByEmail(ctx, tx, dbsqlc.InviteUserToWorkspaceByEmailParams{
			WorkspaceID: workspaceID,
			TeamID:      teamID,
			MemberEmail: memberEmail,
			ExpiresAt:   time.Now().Add(h.config.InvitationExpiryIn),
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
	ownerID int64,
) (int64, int64, error) {
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		return 0, 0, fmt.Errorf(
			"shieldworkspace: failed to begin transaction: %w",
			err,
		)
	}

	defer func() { _ = tx.Rollback(ctx) }()

	workspaceID, err := dbsqlc.New().
		CreateWorkspace(ctx, tx, dbsqlc.CreateWorkspaceParams{
			Name:    name,
			OwnedBy: ownerID,
		})
	if err != nil {
		return 0, 0, fmt.Errorf(
			"shieldworkspace: failed to create workspace: %w",
			err,
		)
	}

	// Create a default team for the workspace
	teamID, err := dbsqlc.New().CreateTeam(ctx, tx, dbsqlc.CreateTeamParams{
		Name:        "Default",
		Handle:      "default",
		WorkspaceID: workspaceID,
		IsSystem:    true,
		Metadata:    nil,
	})
	if err != nil {
		return 0, 0, fmt.Errorf(
			"shieldworkspace: failed to create default team: %w",
			err,
		)
	}

	return workspaceID, teamID, nil
}

// FindWorkspace retrieves a workspace by its ID.
func FindWorkspace(
	ctx context.Context,
	dbtx dbsqlc.DBTX,
	workspaceID int64,
) (*Workspace, error) {
	w, err := dbsqlc.New().FindWorkspaceByID(ctx, dbtx, workspaceID)
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
