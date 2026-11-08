-- Least-privilege grants for the daemon's role, applied by the `grants` compose service
-- (as zenv_ca_owner) after `zenv-ca init` has created the tables. Idempotent.
-- zenv_ca_app can never UPDATE/DELETE/TRUNCATE audit_log, disable its triggers or
-- alter the schema: it owns nothing.
SET search_path TO zenv_ca;
GRANT SELECT, INSERT, UPDATE ON certificates, api_tokens TO zenv_ca_app;
GRANT SELECT, UPDATE ON crl_state TO zenv_ca_app;
GRANT SELECT, INSERT ON audit_log TO zenv_ca_app;
GRANT SELECT ON zenv_ca_schema_version TO zenv_ca_app;
