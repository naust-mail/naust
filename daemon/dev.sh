#!/usr/bin/env bash
# Runs managerd standalone for local frontend development. Everything is
# confined to STORAGE_ROOT (default /tmp/naust-dev) - no real system paths
# are touched, and no other naust services are required.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

STORAGE_ROOT="${STORAGE_ROOT:-/tmp/naust-dev}"
PRIMARY_HOSTNAME="${PRIMARY_HOSTNAME:-dev.example.com}"
# RFC 5737 TEST-NET-3: reserved for documentation/examples, same idea as
# example.com above. Every A record in the zone builder derives from this,
# so leaving it unset makes every A record's value empty.
PUBLIC_IP="${PUBLIC_IP:-203.0.113.1}"

mkdir -p "$STORAGE_ROOT/nsd/zones"

TOKEN_PATH="$STORAGE_ROOT/bootstrap.token"
if [ ! -f "$TOKEN_PATH" ]; then
	CODE=$( (tr -dc 'A-Z0-9' </dev/urandom || true) | head -c 8)
	EXPIRES=$(($(date +%s) + 86400))
	printf '{"code":"%s","expires":%d,"attempts":0}\n' "$CODE" "$EXPIRES" > "$TOKEN_PATH"
	echo "bootstrap code: $CODE (valid 24h, written to $TOKEN_PATH)"
fi
CODE=$(grep -o '"code":"[^"]*"' "$TOKEN_PATH" | cut -d'"' -f4)

go build -o managerd ./cmd/managerd

# postmap and helperd don't exist standalone; both retry loops are
# expected forever in this mode and just add noise.
NOISE='executable file not found|dial unix .*/helper\.sock'

STORAGE_ROOT="$STORAGE_ROOT" ./managerd \
	-primary-hostname="$PRIMARY_HOSTNAME" \
	-public-ip="$PUBLIC_IP" \
	-zones-dir="$STORAGE_ROOT/nsd/zones" \
	-nsd-conf="$STORAGE_ROOT/nsd/zones.conf" \
	-mta-sts-policy="$STORAGE_ROOT/mta-sts.txt" \
	2> >(grep -vE "$NOISE" >&2) &
PID=$!
trap 'kill "$PID" 2>/dev/null' EXIT INT TERM

for _ in $(seq 1 50); do
	curl -s -o /dev/null "http://127.0.0.1:10223/api/meta" && break
	sleep 0.2
done

DEV_EMAIL="test@example.com"
DEV_PASSWORD="testuser123"
BOOTSTRAP_RESULT=$(curl -s -X POST "http://127.0.0.1:10223/api/bootstrap" \
	-H 'Content-Type: application/json' \
	-d "$(printf '{"code":"%s","email":"%s","password":"%s"}' "${CODE:-}" "$DEV_EMAIL" "$DEV_PASSWORD")")
if grep -q '"token"' <<<"$BOOTSTRAP_RESULT"; then
	echo "dev admin ready: $DEV_EMAIL / $DEV_PASSWORD"
else
	echo "bootstrap skipped (probably already set up): $BOOTSTRAP_RESULT"
fi

wait "$PID"
