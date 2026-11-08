#!/usr/bin/env bash
# Runs once, on the first start of an empty postgres data volume (docker-entrypoint-initdb.d).
# Creates the two zenv-ca roles, the database and the schema. The tables are created later
# by `zenv-ca init` as zenv_ca_owner; grants.sql then gives zenv_ca_app DML rights only.
set -euo pipefail

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
    -v owner_pw="$(cat /run/secrets/db_owner_password)" \
    -v app_pw="$(cat /run/secrets/db_app_password)" <<'SQL'
CREATE ROLE zenv_ca_owner LOGIN PASSWORD :'owner_pw';
CREATE ROLE zenv_ca_app   LOGIN PASSWORD :'app_pw';
CREATE DATABASE zenv_ca OWNER zenv_ca_owner;
SQL

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname zenv_ca <<'SQL'
REVOKE ALL ON DATABASE zenv_ca FROM PUBLIC;
GRANT CONNECT ON DATABASE zenv_ca TO zenv_ca_owner, zenv_ca_app;
CREATE SCHEMA zenv_ca AUTHORIZATION zenv_ca_owner;
GRANT USAGE ON SCHEMA zenv_ca TO zenv_ca_app;
SQL
