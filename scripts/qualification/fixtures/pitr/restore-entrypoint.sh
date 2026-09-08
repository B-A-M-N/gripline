#!/usr/bin/env bash
set -euo pipefail

: "${PGDATA:=/var/lib/postgresql/data}"
rm -rf -- "$PGDATA"/*
cp -a /backup/base/. "$PGDATA/"
rm -f "$PGDATA/standby.signal"
cat >>"$PGDATA/postgresql.auto.conf" <<EOF
restore_command = 'cp /archive/%f %p'
recovery_target_time = '${GRIPLINE_PITR_TARGET_TIME:?}'
recovery_target_action = 'promote'
EOF
touch "$PGDATA/recovery.signal"
chown -R postgres:postgres "$PGDATA"
chmod 0700 "$PGDATA"
exec gosu postgres postgres
