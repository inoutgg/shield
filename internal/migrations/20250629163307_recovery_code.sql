-- migration: 20250629163307_recovery_code.sql

CREATE TABLE IF NOT EXISTS shield_recovery_codes (
  id UUID NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
  user_id UUID NOT NULL,
  recovery_code_hash VARCHAR(4095) NOT NULL,
  is_consumable BOOL NOT NULL DEFAULT TRUE,
  evicted_by UUID NULL,
  evicted_at TIMESTAMP WITH TIME ZONE NULL DEFAULT NULL,
  PRIMARY KEY (id),
  FOREIGN KEY (user_id) REFERENCES shield_users (id)
    ON DELETE CASCADE
    ON UPDATE CASCADE,
  FOREIGN KEY (evicted_by) REFERENCES shield_users (id)
    ON DELETE CASCADE
    ON UPDATE CASCADE
);

CREATE INDEX src_user_id_idx ON shield_recovery_codes (user_id);

---- create above / drop below ----

DROP TABLE IF EXISTS shield_recovery_codes;
