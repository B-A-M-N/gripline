#!/usr/bin/env bash
set -euo pipefail

: "${PGDATA:=/var/lib/postgresql/data}"
until pg_isready -h primary -U gripline -d gripline >/dev/null 2>&1; do
	sleep 1
done
if [[ ! -f "$PGDATA/PG_VERSION" ]]; then
	rm -rf -- "$PGDATA"/*
	PGPASSWORD="${PGPASSWORD:?}" pg_basebackup -h primary -U replicator -D "$PGDATA" -Fp -Xs -P -R
	chown -R postgres:postgres "$PGDATA"
	chmod 0700 "$PGDATA"
fi
exec gosu postgres postgres
