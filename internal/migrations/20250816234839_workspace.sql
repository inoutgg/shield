-- migration: 20250816234839_workspace.sql

CREATE TABLE IF NOT EXISTS shield_workspaces (
  id VARCHAR(64) NOT NULL,
  owned_by VARCHAR(64) NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
  name VARCHAR(255) NOT NULL,
  PRIMARY KEY (id),
  UNIQUE (name),

  FOREIGN KEY (owned_by) REFERENCES shield_users (id)
    ON UPDATE CASCADE
);

CREATE TABLE IF NOT EXISTS shield_workspace_members (
  workspace_id VARCHAR(64) NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
  member_id VARCHAR(64) NOT NULL,
  -- metadata may contain arbitrary user-defined information, for instance ACL, etc.
  metadata JSONB NULL,
  PRIMARY KEY (workspace_id, member_id),
  FOREIGN KEY (member_id) REFERENCES shield_users (id)
    ON DELETE CASCADE
    ON UPDATE CASCADE,
  FOREIGN KEY (workspace_id) REFERENCES shield_workspaces (id)
    ON DELETE CASCADE
    ON UPDATE CASCADE
);

CREATE TABLE IF NOT EXISTS shield_workspace_membership_invitations (
  id VARCHAR(64) NOT NULL,
  workspace_id VARCHAR(64) NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
  member_email VARCHAR(255) NOT NULL,
  status VARCHAR(255) NOT NULL DEFAULT 'pending',
  expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
  accepted_at TIMESTAMP WITH TIME ZONE NULL,
  rejected_at TIMESTAMP WITH TIME ZONE NULL,

  CHECK (status IN ('pending', 'accepted', 'rejected')),

  PRIMARY KEY (workspace_id, id),
  FOREIGN KEY (workspace_id) REFERENCES shield_workspaces (id)
    ON DELETE CASCADE
    ON UPDATE CASCADE
);

---- create above / drop below ----

DROP TABLE IF EXISTS shield_workspace_members;
DROP TABLE IF EXISTS shield_workspace_membership_invitations;
DROP TABLE IF EXISTS shield_workspaces;
