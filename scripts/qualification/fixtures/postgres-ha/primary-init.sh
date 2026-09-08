#!/usr/bin/env bash
set -euo pipefail

printf '%s\n' 'host replication replicator 0.0.0.0/0 trust' >>"$PGDATA/pg_hba.conf"
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" -c 'SELECT pg_reload_conf()' >/dev/null
