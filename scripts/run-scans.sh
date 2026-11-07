#!/usr/bin/env bash
# Run the local SAST / SCA / secrets / container scans against a clean checkout.
#
# Usage:
#   scripts/run-scans.sh prepare-db                 # fetch Trivy DB, OSV offline DBs, Semgrep rule packs
#   scripts/run-scans.sh scan <target-dir> <out-dir> <label>
#   scripts/run-scans.sh base-images <target-dir> <out-dir> <label>   # only base-images.json
#
# <target-dir> must be a clean worktree of the commit being measured (e.g.
# `git worktree add --detach ../baseline-4ec80e1 4ec80e1`), so dev files in this
# repo (.venv, tools, tests, requirements-dev.txt) are never counted.
# `scan` never updates databases or rules: the "before" and "after" runs use
# exactly the snapshots fetched by the last `prepare-db`, recorded in
# <out-dir>/TOOL_VERSIONS.txt.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
TOOLS="$REPO/tools"
SEMGREP="$REPO/.venv/Scripts/semgrep"
[ -x "$SEMGREP" ] || SEMGREP="$REPO/.venv/bin/semgrep"
TRIVY_CACHE="$TOOLS/trivy-cache"
RULES_DIR="$TOOLS/semgrep-rules"
export OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY="$TOOLS/osv-db"
export SEMGREP_SEND_METRICS=off
# Semgrep on Windows otherwise writes SARIF in the console code page, not UTF-8.
export PYTHONUTF8=1

SEMGREP_PACKS="p/default p/python p/flask p/javascript p/dockerfile"
OSV_IMAGE="ghcr.io/google/osv-scanner:v2.7.0@sha256:4f3b7e2c64b9d38a5febc5a7e4a3dfef1d1362f726dea7a2ef4762b46469fcd0"

# Path form Docker accepts for bind mounts (C:/... under Git Bash, unchanged elsewhere).
native_path() { if command -v cygpath > /dev/null; then cygpath -m "$1"; else echo "$1"; fi; }

prepare_db() {
    mkdir -p "$RULES_DIR" "$TRIVY_CACHE" "$OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY"
    for pack in $SEMGREP_PACKS; do
        curl -sSfL "https://semgrep.dev/c/$pack" -o "$RULES_DIR/${pack#p/}.yaml"
    done
    date -u +%Y-%m-%dT%H:%M:%SZ > "$RULES_DIR/FETCHED_AT"

    "$TOOLS/trivy" image --cache-dir "$TRIVY_CACHE" --download-db-only
    # The misconfig checks bundle is fetched on first use; scan an empty dir to pull it.
    local tmp; tmp="$(mktemp -d)"
    "$TOOLS/trivy" config --cache-dir "$TRIVY_CACHE" --quiet "$tmp" > /dev/null

    # OSV offline DBs are per ecosystem; a throwaway scan of a PyPI + npm
    # manifest pulls both.
    echo "requests==2.31.0" > "$tmp/requirements.txt"
    echo '{"dependencies":{"truffle":"5.11.4"}}' > "$tmp/package.json"
    "$TOOLS/osv-scanner" scan source --offline-vulnerabilities --download-offline-databases \
        -r "$tmp" > /dev/null 2>&1 || true
    rm -rf "$tmp"
}

record_versions() {
    local out="$1" label="$2" target="$3"
    {
        echo
        echo "# ---- Scan: $label ----"
        echo "scan date (UTC)   $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "target commit     $(git -C "$target" rev-parse HEAD)"
        echo "osv-scanner run   $OSV_IMAGE"
        echo
        echo "## Semgrep rule packs (snapshot used via --config <file>; fetched $(cat "$RULES_DIR/FETCHED_AT"))"
        for pack in $SEMGREP_PACKS; do
            f="$RULES_DIR/${pack#p/}.yaml"
            printf '%-14s sha256 %s  rules %s\n' "$pack" "$(sha256sum "$f" | cut -d' ' -f1)" "$(grep -cE '^\s*- id:|^- id:' "$f")"
        done
        echo
        echo "## Trivy DBs"
        "$TOOLS/trivy" --cache-dir "$TRIVY_CACHE" --version
        echo
        echo "## OSV offline databases (osv-vulnerabilities.storage.googleapis.com/<ecosystem>/all.zip)"
        find "$OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY" -name '*.zip' | sort | while read -r z; do
            printf '%-10s sha256 %s  size %s  downloaded %s\n' \
                "$(basename "$(dirname "$z")")" "$(sha256sum "$z" | cut -d' ' -f1)" \
                "$(stat -c %s "$z")" "$(date -u -r "$z" +%Y-%m-%dT%H:%M:%SZ)"
        done
    } >> "$out/TOOL_VERSIONS.txt"
}

base_image_of() { awk 'toupper($1) == "FROM" { print $2; exit }' "$1"; }

# Write <out>/base-images.json: for each scanned image, its Dockerfile's base
# image, the base digest, and the base's layer diff IDs.
record_base_images() {
    local target="$1" out="$2" label="$3" img df base first=1
    {
        echo "{"
        for pair in "p2p-tracker:$label=p2p/Tracker_server/dockerfile" "p2p-peer:$label=p2p/peer_client/Dockerfile"; do
            img="${pair%%=*}"; df="${pair#*=}"; base="$(base_image_of "$target/$df")"
            [ $first -eq 1 ] || echo ","; first=0
            printf '  "%s": {"dockerfile": "%s", "base": "%s", "base_digest": "%s", "base_diff_ids": %s}' \
                "$img" "$df" "$base" \
                "$(docker image inspect "$base" --format '{{index .RepoDigests 0}}')" \
                "$(docker image inspect "$base" --format '{{json .RootFS.Layers}}')"
        done
        printf '\n}\n'
    } > "$out/base-images.json"
}

scan() {
    local target out label
    target="$(cd "$1" && pwd)"; out="$2"; label="$3"
    mkdir -p "$out"; out="$(cd "$out" && pwd)"
    if [ -n "$(git -C "$target" status --porcelain)" ]; then
        echo "target $target is not a clean checkout" >&2; exit 1
    fi
    # Scan the committed bytes, as CI sees them. With core.autocrlf=true (Git for
    # Windows default) the checkout is CRLF, which breaks Semgrep's Dockerfile parser.
    # Create the worktree with: git -c core.autocrlf=false worktree add --detach <dir> <commit>
    if git -C "$target" ls-files --eol | grep -q 'i/lf *w/crlf'; then
        echo "target $target has CRLF-converted files; recreate it with core.autocrlf=false" >&2; exit 1
    fi

    record_versions "$out" "$label" "$target"

    # All scanners run from inside the target against "." so reports carry
    # repo-relative paths, not this machine's absolute paths.
    cd "$target"

    # SAST: Semgrep (spec packs, from the snapshot). Semgrep prefixes the IDs of
    # rules loaded from a file with the file's directory path, which would leak
    # this machine's paths and stop rule IDs matching the registry's (as in CI).
    # A config at "../<file>" gets no prefix, so the snapshot is copied next to
    # the target for this step only. It is outside the scan scope (copying it
    # into the target does not work: p/default's generic rules ignore --exclude).
    local cfg=() pack f
    trap 'rm -f "$target"/../semgrep-snapshot-*.yaml' EXIT
    for pack in $SEMGREP_PACKS; do
        f="../semgrep-snapshot-${pack#p/}.yaml"
        cp "$RULES_DIR/${pack#p/}.yaml" "$f"
        cfg+=(--config "$f")
    done
    "$SEMGREP" scan "${cfg[@]}" --metrics=off --disable-version-check \
        --sarif --output "$out/semgrep.sarif" .
    rm -f ../semgrep-snapshot-*.yaml
    trap - EXIT

    # SCA: OSV-Scanner (exit 1 = vulns found, which is not an error here). It
    # always reports absolute source paths, so it runs from the official image
    # (same v2.7.0 build as tools/osv-scanner.exe) with the target at /src.
    MSYS_NO_PATHCONV=1 docker run --rm \
        -v "$(native_path "$target"):/src:ro" \
        -v "$(native_path "$OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY"):/osv-db" \
        -e OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=/osv-db \
        "$OSV_IMAGE" scan source --offline-vulnerabilities -r /src --format json \
        > "$out/osv.json" || [ $? -eq 1 ]

    # Secrets: Gitleaks over all history reachable from the target commit; secrets redacted in the report
    "$TOOLS/gitleaks" git . --log-opts="$(git rev-parse HEAD)" \
        --redact --report-format json --report-path "$out/gitleaks.json" --exit-code 0

    # Container and IaC: Trivy
    local t=("$TOOLS/trivy" --cache-dir "$TRIVY_CACHE")
    "${t[@]}" fs --skip-db-update --skip-check-update --scanners vuln,secret,misconfig \
        --format json --output "$out/trivy-fs.json" .
    "${t[@]}" config --skip-check-update --format json --output "$out/trivy-config.json" .

    # Pull each base image first so its layers can be recorded (BuildKit does
    # not keep the base tagged locally); triage uses them to split base-image
    # packages from what the Dockerfile adds.
    docker pull -q "$(base_image_of p2p/Tracker_server/dockerfile)" > /dev/null
    docker pull -q "$(base_image_of p2p/peer_client/Dockerfile)" > /dev/null
    docker build -q -t "p2p-tracker:$label" p2p/Tracker_server
    docker build -q -t "p2p-peer:$label" p2p/peer_client
    record_base_images "$target" "$out" "$label"
    "${t[@]}" image --skip-db-update --skip-check-update --format json \
        --output "$out/trivy-image-tracker.json" "p2p-tracker:$label"
    "${t[@]}" image --skip-db-update --skip-check-update --format json \
        --output "$out/trivy-image-peer.json" "p2p-peer:$label"

    # GitHub warns above 50 MB per file; compress large reports losslessly and
    # deterministically (-n: no name/timestamp in the header).
    find "$out" -maxdepth 1 -name '*.json' -size +50M -exec gzip -n -9 {} \;
}

case "${1:-}" in
    prepare-db) prepare_db ;;
    scan) scan "$2" "$3" "$4" ;;
    base-images) record_base_images "$(cd "$2" && pwd)" "$3" "$4" ;;
    *) sed -n '2,12p' "$0"; exit 2 ;;
esac
