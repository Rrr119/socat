#!/usr/bin/env bash
# Self-contained TLS 1.3 / mutual authentication integration tests for socat.

set -u

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
SOCAT=${SOCAT:-"$SCRIPT_DIR/socat"}
WORKDIR=$(mktemp -d "${TMPDIR:-/tmp}/socat-tls13-mtls.XXXXXX")

PASSED=0
FAILED=0
SERVER_PID=""

cleanup() {
	if [ -n "${SERVER_PID:-}" ]; then
		kill "$SERVER_PID" 2>/dev/null || true
		wait "$SERVER_PID" 2>/dev/null || true
	fi
	rm -rf "$WORKDIR"
}
trap cleanup EXIT INT TERM

if [ ! -x "$SOCAT" ]; then
	echo "socat binary not found at $SOCAT; building it now" >&2
	(make -C "$SCRIPT_DIR" -j2 socat) || exit 2
fi
if ! command -v openssl >/dev/null 2>&1; then
	echo "openssl is required to generate test certificates" >&2
	echo "SKIP: openssl executable not available"
	exit 77
fi
if ! "$SOCAT" -V 2>/dev/null | grep -q "#define WITH_OPENSSL 1"; then
	echo "SKIP: socat was built without OpenSSL support"
	exit 77
fi

openssl req -x509 -newkey rsa:2048 -nodes \
	-keyout "$WORKDIR/ca.key" -out "$WORKDIR/ca.crt" -days 1 \
	-subj "/CN=Socat Test CA" >/dev/null 2>&1

cat >"$WORKDIR/server.ext" <<'EOF'
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,DNS:server,IP:127.0.0.1
EOF

cat >"$WORKDIR/client.ext" <<'EOF'
basicConstraints=CA:FALSE
keyUsage=digitalSignature
extendedKeyUsage=clientAuth
EOF

openssl req -newkey rsa:2048 -nodes \
	-keyout "$WORKDIR/server.key" -out "$WORKDIR/server.csr" \
	-subj "/CN=server" >/dev/null 2>&1
openssl x509 -req -in "$WORKDIR/server.csr" \
	-CA "$WORKDIR/ca.crt" -CAkey "$WORKDIR/ca.key" -CAcreateserial \
	-out "$WORKDIR/server.crt" -days 1 \
	-extfile "$WORKDIR/server.ext" >/dev/null 2>&1
cat "$WORKDIR/server.key" "$WORKDIR/server.crt" >"$WORKDIR/server.pem"

openssl req -newkey rsa:2048 -nodes \
	-keyout "$WORKDIR/client.key" -out "$WORKDIR/client.csr" \
	-subj "/CN=test-client" >/dev/null 2>&1
openssl x509 -req -in "$WORKDIR/client.csr" \
	-CA "$WORKDIR/ca.crt" -CAkey "$WORKDIR/ca.key" -CAcreateserial \
	-out "$WORKDIR/client.crt" -days 1 \
	-extfile "$WORKDIR/client.ext" >/dev/null 2>&1
cat "$WORKDIR/client.key" "$WORKDIR/client.crt" >"$WORKDIR/client.pem"

openssl req -x509 -newkey rsa:2048 -nodes \
	-keyout "$WORKDIR/bad.key" -out "$WORKDIR/bad.crt" -days 1 \
	-subj "/CN=untrusted-client" >/dev/null 2>&1
cat "$WORKDIR/bad.key" "$WORKDIR/bad.crt" >"$WORKDIR/bad.pem"

wait_for_pattern() {
	local pattern=$1
	local file=$2
	local tries=${3:-50}
	local i

	for ((i = 0; i < tries; i++)); do
		if grep -Eq "$pattern" "$file" 2>/dev/null; then
			return 0
		fi
		sleep 0.1
	done
	return 1
}

start_server() {
	local name=$1
	local address_type=$2
	local options=$3
	local backend=$4
	local stderr_file="$WORKDIR/$name.server.err"
	local stdout_file="$WORKDIR/$name.server.out"

	"$SOCAT" -d -d \
		"$address_type:0,bind=127.0.0.1,reuseaddr,$options" \
		"$backend" \
		>"$stdout_file" 2>"$stderr_file" &
	SERVER_PID=$!

	if ! wait_for_pattern \
		"listening on AF=2 127\\.0\\.0\\.1:[0-9]+" \
		"$stderr_file"; then
		echo "server $name did not start" >&2
		cat "$stderr_file" >&2
		return 1
	fi

	SERVER_PORT=$(sed -nE \
		's/.*listening on AF=2 127\.0\.0\.1:([0-9]+).*/\1/p' \
		"$stderr_file" | head -n1)
	if [ -z "$SERVER_PORT" ]; then
		echo "could not determine port for $name" >&2
		cat "$stderr_file" >&2
		return 1
	fi
	return 0
}

stop_server() {
	if [ -n "${SERVER_PID:-}" ]; then
		kill "$SERVER_PID" 2>/dev/null || true
		wait "$SERVER_PID" 2>/dev/null || true
		SERVER_PID=""
	fi
}

report_failure() {
	local name=$1
	local message=$2

	echo "FAIL $name: $message" >&2
	for file in "$WORKDIR/$name.client.out" "$WORKDIR/$name.client.err" \
		    "$WORKDIR/$name.server.out" "$WORKDIR/$name.server.err"; do
		if [ -f "$file" ]; then
			echo "----- $file" >&2
			cat "$file" >&2
		fi
	done
	FAILED=$((FAILED + 1))
}

report_success() {
	local name=$1

	echo "PASS $name"
	PASSED=$((PASSED + 1))
}

run_tunnel_case() {
	local name=$1
	local server_type=$2
	local client_type=$3
	local backend=$4
	local server_options=$5
	local client_options=$6
	local require_server_peer=$7
	local payload="payload-$name-$RANDOM"
	local client_out="$WORKDIR/$name.client.out"
	local client_err="$WORKDIR/$name.client.err"
	local server_err="$WORKDIR/$name.server.err"

	if ! start_server "$name" "$server_type" "$server_options" "$backend"; then
		FAILED=$((FAILED + 1))
		return 1
	fi

	printf '%s\n' "$payload" | timeout 10 "$SOCAT" -d -d - \
		"$client_type:127.0.0.1:$SERVER_PORT,$client_options" \
		>"$client_out" 2>"$client_err"
	local client_rc=$?

	if [ "$client_rc" -ne 0 ]; then
		report_failure "$name" "client exited with $client_rc"
		stop_server
		return 1
	fi
	if [ "$(cat "$client_out")" != "$payload" ]; then
		report_failure "$name" "echoed payload did not match"
		stop_server
		return 1
	fi
	if ! wait_for_pattern "SSL proto version used: TLSv1\\.3" "$client_err"; then
		report_failure "$name" "client did not negotiate TLS 1.3"
		stop_server
		return 1
	fi
	if ! wait_for_pattern "SSL proto version used: TLSv1\\.3" "$server_err"; then
		report_failure "$name" "server did not negotiate TLS 1.3"
		stop_server
		return 1
	fi
	if ! grep -q "trusting certificate, commonName matches" "$client_err"; then
		report_failure "$name" "client did not verify server certificate name"
		stop_server
		return 1
	fi
	if [ "$require_server_peer" = "yes" ] && \
	   ! grep -q "trusting certificate" "$server_err"; then
		report_failure "$name" "server did not verify client certificate"
		stop_server
		return 1
	fi

	report_success "$name"
	stop_server
}

run_negative_case() {
	local name=$1
	local client_options=$2
	local expected_pattern=$3
	local payload="negative-$name-$RANDOM"
	local client_out="$WORKDIR/$name.client.out"
	local client_err="$WORKDIR/$name.client.err"
	local server_err="$WORKDIR/$name.server.err"
	local server_options="verify=1,cert=$WORKDIR/server.pem,cafile=$WORKDIR/ca.crt,min-proto-version=TLS1.3"

	if ! start_server "$name" "OPENSSL-LISTEN" "$server_options" "PIPE"; then
		FAILED=$((FAILED + 1))
		return 1
	fi

	printf '%s\n' "$payload" | timeout 10 "$SOCAT" -d -d - \
		"OPENSSL-CONNECT:127.0.0.1:$SERVER_PORT,$client_options" \
		>"$client_out" 2>"$client_err" || true

	if [ -s "$client_out" ]; then
		report_failure "$name" "rejected client received application data"
		stop_server
		return 1
	fi
	if ! wait_for_pattern "$expected_pattern" "$server_err" && \
	   ! grep -Eq "$expected_pattern" "$client_err"; then
		report_failure "$name" "expected verification failure not found"
		stop_server
		return 1
	fi

	report_success "$name"
	stop_server
}

tls_exact="min-proto-version=TLS1.3,max-proto-version=TLS1.3"

# Scenario 1: TLS 1.3 with the client verifying the server certificate.
run_tunnel_case \
	"01-server-auth" \
	"OPENSSL-LISTEN" "OPENSSL-CONNECT" "EXEC:cat" \
	"verify=0,cert=$WORKDIR/server.pem,$tls_exact" \
	"verify=1,cafile=$WORKDIR/ca.crt,commonname=server,$tls_exact" \
	"no"

# Scenario 2: TLS 1.3 with mutual certificate verification.
run_tunnel_case \
	"02-mutual-auth" \
	"OPENSSL-LISTEN" "OPENSSL-CONNECT" "EXEC:cat" \
	"verify=1,cert=$WORKDIR/server.pem,cafile=$WORKDIR/ca.crt,$tls_exact" \
	"verify=1,cafile=$WORKDIR/ca.crt,cert=$WORKDIR/client.pem,commonname=server,$tls_exact" \
	"yes"

# Scenario 3: existing SSL address aliases and PIPE remain compatible.
run_tunnel_case \
	"03-ssl-alias-pipe" \
	"SSL-L" "SSL" "PIPE" \
	"verify=1,cert=$WORKDIR/server.pem,cafile=$WORKDIR/ca.crt,min-version=TLS1.3" \
	"verify=1,cafile=$WORKDIR/ca.crt,cert=$WORKDIR/client.pem,commonname=server,min-version=TLS1.3" \
	"yes"

# Negative checks make the meaning of "verification correct" explicit.
run_negative_case \
	"04-wrong-server-ca" \
	"verify=1,cafile=$WORKDIR/bad.crt,commonname=server,cert=$WORKDIR/client.pem" \
	"certificate verify failed"
run_negative_case \
	"05-untrusted-client" \
	"verify=1,cafile=$WORKDIR/ca.crt,commonname=server,cert=$WORKDIR/bad.pem" \
	"certificate verify failed"
run_negative_case \
	"06-missing-client-cert" \
	"verify=1,cafile=$WORKDIR/ca.crt,commonname=server" \
	"peer did not return a certificate|certificate verify failed"

echo
echo "TLS tests: $PASSED passed, $FAILED failed"
if [ "$FAILED" -ne 0 ]; then
	exit 1
fi
