-- Manual post-rollout cleanup; never register this in startup migrations.
-- Requires every authn replica and caller to have stopped using avatar fields.
-- psql -X -v ON_ERROR_STOP=1 -v avatar_rollout_complete=yes \
--   -v expected_database=csar_authn -f scripts/retire-avatar-columns.sql
\set ON_ERROR_STOP on
\if :{?avatar_rollout_complete}
\else
  DO $$ BEGIN RAISE EXCEPTION 'Refusing cleanup: avatar_rollout_complete is required.'; END $$;
\endif
\if :avatar_rollout_complete
\else
  DO $$ BEGIN RAISE EXCEPTION 'Refusing cleanup: coordinated avatar rollout must be complete.'; END $$;
\endif
\if :{?expected_database}
\else
  DO $$ BEGIN RAISE EXCEPTION 'Refusing cleanup: expected_database is required.'; END $$;
\endif
SELECT current_database() = :'expected_database' AS correct_database \gset
\if :correct_database
\else
  DO $$ BEGIN RAISE EXCEPTION 'Refusing cleanup: database does not match expected_database.'; END $$;
\endif
BEGIN;
SET LOCAL lock_timeout = '3s';
SET LOCAL statement_timeout = '30s';
LOCK TABLE public.users, public.oauth_accounts IN ACCESS EXCLUSIVE MODE;
-- Counts only; do not print user IDs, storage keys or provider URLs.
SELECT count(*) FILTER (WHERE avatar_storage_key <> '') AS uploaded_avatar_users,
       count(*) FILTER (WHERE avatar_url <> '') AS imported_photo_users
FROM public.users;
SELECT count(*) FILTER (WHERE avatar_url <> '') AS provider_photo_accounts
FROM public.oauth_accounts;
ALTER TABLE public.users
  DROP COLUMN avatar_storage_key,
  DROP COLUMN avatar_preview_storage_key,
  DROP COLUMN avatar_master_storage_key,
  DROP COLUMN avatar_url;
ALTER TABLE public.oauth_accounts DROP COLUMN avatar_url;
COMMIT;
