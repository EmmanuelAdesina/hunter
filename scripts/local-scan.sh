#!/usr/bin/env bash
#
# local-scan.sh - run one scan from a working tree, for development.
#
# This is a thin wrapper. All behaviour lives in the Go binary; the only logic
# here is argument handling and the credential check, because a developer running
# this by hand should not have to remember which environment variables are
# required.
#
# It never writes credentials anywhere, and never passes them as arguments.

set -euo pipefail

readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PROFILE="configs/profiles/personal.yaml"
STATE_DIR="state"
BIN="${BIN:-}"
DRY_RUN=1
FULL=0

usage() {
	cat <<'USAGE'
Usage: scripts/local-scan.sh [options]

Options:
  --live             Actually send email. Without it the run is a dry run.
  --profile <path>   Profile to load (default: configs/profiles/personal.yaml).
  --state <dir>      State directory (default: state).
  --full             Traverse the whole listing.
  --bin <path>       Use an existing binary instead of building.
  -h, --help         Show this message.

Email delivery reads these environment variables:
  EMAIL_SMTP_HOST, EMAIL_SMTP_PORT, EMAIL_USERNAME, EMAIL_PASSWORD,
  ALERT_RECIPIENT, and optionally EMAIL_FROM_NAME.

With --live the script refuses to run unless all of them are set, so a dry run
cannot silently be mistaken for a real one.
USAGE
}

while [ $# -gt 0 ]; do
	case "$1" in
	--live)
		DRY_RUN=0
		shift
		;;
	--full)
		FULL=1
		shift
		;;
	--profile)
		PROFILE="${2:?--profile requires a path}"
		shift 2
		;;
	--state)
		STATE_DIR="${2:?--state requires a directory}"
		shift 2
		;;
	--bin)
		BIN="${2:?--bin requires a path}"
		shift 2
		;;
	-h | --help)
		usage
		exit 0
		;;
	*)
		echo "unknown option: $1" >&2
		usage >&2
		exit 2
		;;
	esac
done

require_credentials() {
	local missing=()
	for name in EMAIL_SMTP_HOST EMAIL_SMTP_PORT EMAIL_USERNAME EMAIL_PASSWORD ALERT_RECIPIENT; do
		if [ -z "${!name:-}" ]; then
			missing+=("$name")
		fi
	done
	if [ ${#missing[@]} -gt 0 ]; then
		echo "cannot send email; these are not set: ${missing[*]}" >&2
		echo "run without --live for a dry run, or export the missing variables" >&2
		return 1
	fi
}

if [ "$DRY_RUN" -eq 0 ]; then
	require_credentials
fi

if [ -z "$BIN" ]; then
	echo "building hunter..." >&2
	go build -o ./bin/hunter ./cmd/hunter
	BIN="./bin/hunter"
fi

args=(scan --profile "$PROFILE" --state "$STATE_DIR")
if [ "$DRY_RUN" -eq 1 ]; then
	args+=(--dry-run)
fi
if [ "$FULL" -eq 1 ]; then
	args+=(--full)
fi

exec "$BIN" "${args[@]}"
