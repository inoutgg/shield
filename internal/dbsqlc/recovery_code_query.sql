-- name: CreateRecoveryCodeBatch :copyfrom
INSERT INTO shield_recovery_codes
  (id, user_id, recovery_code_hash, is_consumable)
VALUES
  (@id, @user_id, @recovery_code_hash, @is_consumable);

-- name: EvictUnconsumedRecoveryCodeBatch :exec
UPDATE shield_recovery_codes
SET
  evicted_by = @evicted_by,
  evicted_at = NOW()
WHERE user_id = @user_id AND is_consumable = TRUE;
