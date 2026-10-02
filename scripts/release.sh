#!/usr/bin/env bash
#
# release.sh - build portable binaries locally.
#
# Mirrors what .github/workflows/release.yml does, so that a release can be
# produced and verified before it is tagged. Each binary is built twice and
# compared: a build that is not reproducible is a build whose contents cannot be
# reasoned about.

set -euo pipefail

readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

VERSION="${1:-dev}"
readonly VERSION
readonly OUT="dist"

TARGETS=(
	linux/amd64
	linux/arm64
	darwin/amd64
	darwin/arm64
	windows/amd64
)

main() {
	echo "building hunter ${VERSION}"

	if ! command -v go >/dev/null 2>&1; then
		echo "go is required but was not found on PATH" >&2
		exit 1
	fi

	rm -rf "$OUT"
	mkdir -p "$OUT"

	local target os arch binary
	for target in "${TARGETS[@]}"; do
		os="${target%%/*}"
		arch="${target##*/}"
		binary="${OUT}/hunter_${os}_${arch}"
		if [ "$os" = "windows" ]; then
			binary="${binary}.exe"
		fi

		echo "  ${os}/${arch}"
		build "$os" "$arch" "$binary"

		# Reproducibility: identical inputs must produce identical bytes.
		build "$os" "$arch" "${binary}.repeat"
		if ! cmp -s "$binary" "${binary}.repeat"; then
			echo "build for ${target} is not reproducible" >&2
			rm -f "${binary}.repeat"
			exit 1
		fi
		rm -f "${binary}.repeat"
	done

	(
		cd "$OUT"
		sha256sum hunter_* >../SHA256SUMS
	)

	echo
	echo "artifacts:"
	ls -la "$OUT"
	echo
	echo "checksums:"
	cat SHA256SUMS
}

build() {
	local os="$1" arch="$2" output="$3"
	CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" \
		go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
		-o "$output" ./cmd/hunter
}

main "$@"
