-- name: CreateWorkspace :one
INSERT INTO shield_workspaces (id, owned_by, name)
VALUES (@workspace_id, @owned_by, @name)
RETURNING *;

-- name: FindWorkspaceByID :one
SELECT *
FROM shield_workspaces
WHERE id = @id;

-- name: InviteUserToWorkspaceByEmail :exec
INSERT INTO shield_workspace_membership_invitations (id, workspace_id, member_email, expires_at)
VALUES (@invitation_id, @workspace_id, @member_email, @expires_at);

-- name: AcceptWorkspaceInvitation :exec
UPDATE shield_workspace_membership_invitations
SET status = 'accepted', accepted_at = NOW(), expires_at = NOW()
WHERE id = @invitation_id;

-- name: RejectWorkspaceInvitation :exec
UPDATE shield_workspace_membership_invitations
SET status = 'rejected', rejected_at = NOW(), expires_at = NOW()
WHERE id = @invitation_id;

-- name: TransferWorkspaceOwnership :exec
UPDATE shield_workspaces
SET owned_by = @new_owner_id
WHERE id = @workspace_id;
