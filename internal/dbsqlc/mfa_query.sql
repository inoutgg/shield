-- name: GetUserMFAs :many
SELECT * FROM shield_user_mfas WHERE user_id = @user_id;
