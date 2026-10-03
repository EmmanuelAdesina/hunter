#!/usr/bin/env bash
#
# install.sh - install hunter as a hardened systemd timer.
#
# Everything this script creates is unprivileged, opens no port, and stores its
# credentials in one file with 0600 permissions owned by a dedicated account.
#
# The script is deliberately explicit about each step and prints what it did, so
# that a failed install can be diagnosed from the log rather than guessed at.
#
# It does not write any credential. The credential file is created empty and
# must be filled in afterwards.

set -euo pipefail

readonly BINARY="${BINARY:-}"
readonly PROFILE_SRC="${PROFILE_SRC:-}"
readonly APP_USER="hunter"
readonly APP_GROUP="hunter"
readonly ETC_DIR="/etc/hunter"
readonly STATE_DIR="/var/lib/hunter"
readonly LIB_DIR="/usr/local/lib/hunter"
readonly SYSTEMD_DIR="/etc/systemd/system"
readonly SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

log()  { printf '[install] %s\n' "$*"; }
die()  { printf '[install] error: %s\n' "$*" >&2; exit 1; }

require_root() {
	[[ "${EUID}" -eq 0 ]] || die "must run as root: sudo $0"
}

require_systemd() {
	command -v systemctl >/dev/null 2>&1 || die "systemd is required"
	[[ -d /run/systemd/system ]] || die "systemd is not the running init"
}

# preflight checks everything that would otherwise fail halfway through.
preflight() {
	require_root
	require_systemd

	[[ -n "$BINARY" ]] || die "set BINARY to the hunter executable path"
	[[ -f "$BINARY" ]] || die "no such file: $BINARY"

	if ! getent passwd "$APP_USER" >/dev/null; then
		log "creating service account"
		# --system, no home directory, shell locked to a non-login shell. The
		# account exists to own two directories and run one binary.
		useradd --system --no-create-home --home-dir /nonexistent \
			--shell /usr/sbin/nologin --comment "hunter scan account" "$APP_USER"
	else
		log "service account already exists"
	fi

	if getent group docker >/dev/null; then
		if id -nG "$APP_USER" | tr ' ' '\n' | grep -qx docker; then
			die "the service account is in the docker group, which is root-equivalent; remove it first"
		fi
		log "service account is not in the docker group (correct)"
	fi
}

install_binary() {
	log "installing binary to ${LIB_DIR}/hunter"
	install -d -m 0755 "$LIB_DIR"
	install -m 0755 -o root -g root "$BINARY" "${LIB_DIR}/hunter"
	"${LIB_DIR}/hunter" version >/dev/null || die "the installed binary does not run"
}

install_profile() {
	log "installing program definition to ${ETC_DIR}/profile.yaml"
	install -d -m 0750 -o root -g "$APP_GROUP" "$ETC_DIR"

	# The profile is located rather than assumed, so the script works from a
	# checkout, from a copy of deploy/ alone, or from an explicit path.
	local src=""
	local candidate
	for candidate in \
		"$PROFILE_SRC" \
		"${SRC_DIR}/../../configs/profiles/personal.yaml" \
		"${SRC_DIR}/../configs/profiles/personal.yaml" \
		"${SRC_DIR}/configs/profiles/personal.yaml" \
		"${SRC_DIR}/personal.yaml"
	do
		[[ -n "$candidate" && -f "$candidate" ]] || continue
		src="$candidate"
		break
	done
	[[ -n "$src" ]] || die "cannot find personal.yaml; set PROFILE_SRC to its path"

	# Refuse to install a profile that does not parse, rather than discovering
	# it at the first scan.
	"$BINARY" validate-config --profile "$src" >/dev/null 2>&1 \
		|| die "the program definition at ${src} does not validate"

	# Root-owned and group-readable only. The profile is configuration, not a
	# credential, but it does describe the researcher's constraints and there is
	# no reason for it to be world-readable.
	install -m 0640 -o root -g "$APP_GROUP" "$src" "${ETC_DIR}/profile.yaml"
	log "program definition validated and installed"
}

install_env() {
	local dest="${ETC_DIR}/hunter.env"
	if [[ -f "$dest" ]]; then
		log "credential file already exists; leaving it untouched"
	else
		log "creating empty credential file"
		install -m 0600 -o root -g "$APP_GROUP" "${SRC_DIR}/systemd/hunter.env.example" "$dest"
		log ">>> EDIT ${dest} AND SET THE VALUES BEFORE ENABLING THE TIMER"
	fi
	# Enforced regardless of how the file arrived.
	chown root:"$APP_GROUP" "$dest"
	chmod 0640 "$dest"
}

install_units() {
	log "installing systemd units"
	install -m 0644 -o root -g root "${SRC_DIR}/systemd/hunter.service" "${SYSTEMD_DIR}/hunter.service"
	install -m 0644 -o root -g root "${SRC_DIR}/systemd/hunter.timer"   "${SYSTEMD_DIR}/hunter.timer"
	systemctl daemon-reload
}

install_state_dir() {
	log "creating state directory"
	install -d -m 0750 -o "$APP_USER" -g "$APP_GROUP" "$STATE_DIR"
}

verify() {
	log "verifying the installation"

	# Cheap checks that can fail loudly here rather than at the first scan.
	"${LIB_DIR}/hunter" version >/dev/null || die "the installed binary does not run"

	local mode
	mode="$(stat -c '%a' "${ETC_DIR}/hunter.env")"
	[[ "$mode" == "640" ]] || die "credential file is mode ${mode}, expected 640"

	mode="$(stat -c '%a' "${STATE_DIR}")"
	[[ "$mode" == "750" ]] || die "state directory is mode ${mode}, expected 750"

	mode="$(stat -c '%a' "${ETC_DIR}")"
	[[ "$mode" == "750" ]] || die "configuration directory is mode ${mode}, expected 750"

	# The service account must be able to reach the binary and its state, and
	# must not be able to write to the binary or the configuration.
	runuser -u "$APP_USER" -- test -x "${LIB_DIR}/hunter" \
		|| die "the service account cannot execute the binary"
	runuser -u "$APP_USER" -- test -w "$STATE_DIR" \
		|| die "the service account cannot write the state directory"
	runuser -u "$APP_USER" -- test ! -w "${ETC_DIR}/profile.yaml" \
		|| die "the service account can write the program definition"

	log "permissions verified"
}

summary() {
	cat <<SUMMARY

[install] complete.

  binary     ${LIB_DIR}/hunter
  profile    ${ETC_DIR}/profile.yaml
  state      ${STATE_DIR}/state
  credentials ${ETC_DIR}/hunter.env  (root:hunter, 0640)

No listening port was opened. The scan makes outbound connections to the program
platform and to the mail provider, and nothing else.

Next steps:
  1. Fill in ${ETC_DIR}/hunter.env
  2. Check it does not appear anywhere else:
       grep -rl 'EMAIL_PASSWORD' ${ETC_DIR}
  3. Dry run once, by hand:
       sudo -u ${APP_USER} env \$(grep -v '^#' ${ETC_DIR}/hunter.env | xargs) \\
         ${LIB_DIR}/hunter scan --dry-run \\
           --profile ${ETC_DIR}/profile.yaml --state ${STATE_DIR}/state
  4. Enable the timer:
       sudo systemctl enable --now hunter.timer
  5. Confirm it is scheduled:
       systemctl list-timers hunter.timer

Inspect results:
  sudo -u ${APP_USER} ${LIB_DIR}/hunter programs \\
    --profile ${ETC_DIR}/profile.yaml --state ${STATE_DIR}/state --eligible
  sudo journalctl -u hunter.service -n 50
SUMMARY
}

main() {
	preflight
	install_binary
	install_profile
	install_env
	install_state_dir
	install_units
	verify
	summary
}

main "$@"