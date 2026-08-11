#!/bin/bash

# 0-vuln_inventory.sh
#
# MedDefense - Patch Management
# Task 0: Vulnerability Inventory
#
# Enumerates installed packages, identifies available upgrades,
# determines the source pocket, extracts CVEs, correlates them
# against cve_feed.json, and writes vulnerability_inventory.json.
#
# Requirements:
#   - bash
#   - dpkg-query
#   - apt
#   - apt-cache
#   - apt-get
#   - jq
#
# Output:
#   vulnerability_inventory.json

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_FILE="${SCRIPT_DIR}/vulnerability_inventory.json"
CVE_FEED="${SCRIPT_DIR}/cve_feed.json"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

INSTALLED_FILE="${TMP_DIR}/installed_packages"
UPGRADABLE_FILE="${TMP_DIR}/upgradable_packages"
PACKAGES_JSON="${TMP_DIR}/packages.json"

log() {
    printf '[INFO] %s\n' "$*" >&2
}

warn() {
    printf '[WARN] %s\n' "$*" >&2
}

die() {
    printf '[ERROR] %s\n' "$*" >&2
    exit 1
}

# ---------------------------------------------------------------------------
# Dependency checks
# ---------------------------------------------------------------------------

command -v dpkg-query >/dev/null 2>&1 ||
    die "dpkg-query is required."

command -v apt >/dev/null 2>&1 ||
    die "apt is required."

command -v apt-cache >/dev/null 2>&1 ||
    die "apt-cache is required."

command -v apt-get >/dev/null 2>&1 ||
    die "apt-get is required."

command -v jq >/dev/null 2>&1 ||
    die "jq is required."

if [[ ! -f "$CVE_FEED" ]]; then
    die "CVE feed not found: $CVE_FEED"
fi

# ---------------------------------------------------------------------------
# Validate CVE feed
# ---------------------------------------------------------------------------

if ! jq empty "$CVE_FEED" >/dev/null 2>&1; then
    die "Invalid JSON in CVE feed: $CVE_FEED"
fi

# ---------------------------------------------------------------------------
# T0.1 - Enumerate installed packages
#
# Required project command:
# dpkg-query -W -f='${binary:Package} ${Version} ${Status}\n'
# ---------------------------------------------------------------------------

log "Enumerating installed packages..."

if ! dpkg-query -W -f='${binary:Package} ${Version} ${Status}\n' \
    > "$INSTALLED_FILE"; then
    die "Failed to enumerate installed packages."
fi

# ---------------------------------------------------------------------------
# T0.2 - Find packages with available upgrades
#
# apt list --upgradable output normally looks like:
#
# apache2/jammy-updates 2.4.x amd64 [upgradable from: 2.4.y]
#
# We only need the package name here. Installed versions are obtained
# directly from dpkg-query so the inventory has a single authoritative
# source for installed state.
# ---------------------------------------------------------------------------

log "Checking for available package upgrades..."

if ! apt list --upgradable 2>/dev/null |
    sed '1d' |
    awk -F/ 'NF >= 2 {print $1}' |
    sed '/^$/d' |
    sort -u > "$UPGRADABLE_FILE"; then
    die "Failed to enumerate upgradable packages."
fi

# ---------------------------------------------------------------------------
# Helper: installed version
# ---------------------------------------------------------------------------

get_installed_version() {
    local package="$1"

    dpkg-query -W -f='${Version}' "$package" 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# Helper: candidate version
# ---------------------------------------------------------------------------

get_candidate_version() {
    local package="$1"

    apt-cache policy "$package" 2>/dev/null |
        awk '/^[[:space:]]*\*\*\*/ {
            print $2
            exit
        }'
}

# ---------------------------------------------------------------------------
# Helper: determine source pocket
#
# Example:
#   jammy-security
#   jammy-updates
#   jammy-backports
#
# apt-cache policy is used as required by the project.
# ---------------------------------------------------------------------------

get_source_pocket() {
    local package="$1"
    local candidate
    local policy_line

    candidate="$(get_candidate_version "$package")"

    if [[ -z "$candidate" ]]; then
        printf '%s\n' "unknown"
        return
    fi

    policy_line="$(
        apt-cache policy "$package" 2>/dev/null |
        awk -v version="$candidate" '
            $1 == version {
                print $0
                exit
            }
        '
    )"

    case "$policy_line" in
        *"-security"*)
            printf '%s\n' "security"
            ;;
        *"-updates"*)
            printf '%s\n' "updates"
            ;;
        *"-backports"*)
            printf '%s\n' "backports"
            ;;
        *)
            # Try extracting the pocket from the repository URL when
            # the policy output does not contain it directly.
            local repository

            repository="$(
                apt-cache policy "$package" 2>/dev/null |
                awk -v version="$candidate" '
                    $1 == version {
                        found=1
                        next
                    }

                    found && /^[[:space:]]+[0-9]+[[:space:]]+http/ {
                        print $2
                        exit
                    }
                '
            )"

            case "$repository" in
                *"/security"*)
                    printf '%s\n' "security"
                    ;;
                *"/updates"*)
                    printf '%s\n' "updates"
                    ;;
                *"/backports"*)
                    printf '%s\n' "backports"
                    ;;
                *)
                    printf '%s\n' "unknown"
                    ;;
            esac
            ;;
    esac
}

# ---------------------------------------------------------------------------
# Helper: extract CVEs from apt-get changelog
#
# The command can fail because:
#   - network is unavailable
#   - changelog is unavailable
#   - package does not publish a changelog
#
# Failure is intentionally non-fatal.
# ---------------------------------------------------------------------------

get_cves_from_changelog() {
    local package="$1"
    local changelog_file="$TMP_DIR/changelog"

    rm -f "$changelog_file"

    if apt-get changelog "$package" > "$changelog_file" 2>/dev/null; then
        grep -Eo 'CVE-[0-9]{4}-[0-9]{4,}' "$changelog_file" |
            sort -u || true
    fi
}

# ---------------------------------------------------------------------------
# Helper: fallback to locally cached Ubuntu Security Notice mappings
#
# The project specifies:
# /usr/share/ubuntu-advantage-tools
#
# The exact local layout can differ between Ubuntu releases, so this
# searches regular files beneath that directory for CVE identifiers.
# ---------------------------------------------------------------------------

get_cves_from_usn_cache() {
    local package="$1"
    local usn_dir="/usr/share/ubuntu-advantage-tools"

    [[ -d "$usn_dir" ]] || return 0

    # Search files containing both the package name and a CVE identifier.
    # Errors are suppressed because some files may be inaccessible or
    # non-textual.
    grep -RIl -- "$package" "$usn_dir" 2>/dev/null |
        while IFS= read -r file; do
            grep -Eo 'CVE-[0-9]{4}-[0-9]{4,}' "$file" 2>/dev/null || true
        done |
        sort -u
}

# ---------------------------------------------------------------------------
# Helper: retrieve CVEs for a package
#
# Changelog is preferred. Local USN mapping is fallback.
# ---------------------------------------------------------------------------

get_package_cves() {
    local package="$1"
    local cves

    cves="$(get_cves_from_changelog "$package")"

    if [[ -n "$cves" ]]; then
        printf '%s\n' "$cves"
        return
    fi

    get_cves_from_usn_cache "$package"
}

# ---------------------------------------------------------------------------
# Helper: obtain maximum CVSS from cve_feed.json
#
# Missing CVEs are ignored as explicitly required by the project.
# ---------------------------------------------------------------------------

get_max_cvss() {
    local cve_file="$1"

    jq -r --arg cve "$cve_file" '
        [
            .. |
            objects |
            select(
                (.cve? == $cve) or
                (.id? == $cve) or
                (.cve_id? == $cve)
            ) |
            (.cvss? // .cvss_score? // .base_score?)
        ]
        | map(select(type == "number"))
        | if length == 0 then
            empty
          else
            max
          end
    ' "$CVE_FEED" 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# Helper: determine whether CVE is in CISA KEV
# ---------------------------------------------------------------------------

is_in_cisa_kev() {
    local cve="$1"

    jq -e --arg cve "$cve" '
        any(
            .. |
            objects |
            select(
                (.cve? == $cve) or
                (.id? == $cve) or
                (.cve_id? == $cve)
            ) |
            (
                (.in_cisa_kev? == true) or
                (.cisa_kev? == true) or
                (.kev? == true)
            )
        )
    ' "$CVE_FEED" >/dev/null 2>&1
}

# ---------------------------------------------------------------------------
# Helper: CVSS -> severity
#
# CVSS v3-style thresholds:
#   0.0        none
#   0.1-3.9    low
#   4.0-6.9    medium
#   7.0-8.9    high
#   9.0-10.0   critical
# ---------------------------------------------------------------------------

severity_from_cvss() {
    local score="$1"

    awk -v score="$score" '
        BEGIN {
            if (score >= 9.0)
                print "critical";
            else if (score >= 7.0)
                print "high";
            else if (score >= 4.0)
                print "medium";
            else if (score > 0.0)
                print "low";
            else
                print "unknown";
        }
    '
}

# ---------------------------------------------------------------------------
# Build JSON
# ---------------------------------------------------------------------------

log "Building vulnerability inventory..."

printf '%s\n' '[]' > "$PACKAGES_JSON"

while IFS= read -r package; do

    [[ -z "$package" ]] && continue

    installed_version="$(get_installed_version "$package")"
    candidate_version="$(get_candidate_version "$package")"
    source_pocket="$(get_source_pocket "$package")"

    [[ -z "$installed_version" ]] && continue
    [[ -z "$candidate_version" ]] && continue

    log "Processing $package: $installed_version -> $candidate_version"

    # Only security-pocket upgrades require CVE extraction according
    # to the project instructions.
    if [[ "$source_pocket" != "security" ]]; then
        continue
    fi

    cves="$(get_package_cves "$package")"

    # No CVE mapping available. The package is still an upgradeable
    # security package, but the required vulnerability inventory is
    # based on known CVEs.
    if [[ -z "$cves" ]]; then
        warn "No CVE mapping found for $package"
        continue
    fi

    cve_json="$(
        printf '%s\n' "$cves" |
            jq -R -s '
                split("\n")
                | map(select(length > 0))
                | unique
            '
    )"

    max_cvss="$(
        while IFS= read -r cve; do
            [[ -z "$cve" ]] && continue
            get_max_cvss "$cve"
        done <<< "$cves" |
        awk '
            BEGIN { max = 0; found = 0 }
            $1 ~ /^[0-9]+([.][0-9]+)?$/ {
                if ($1 > max)
                    max = $1
                found = 1
            }
            END {
                if (found)
                    printf "%.1f\n", max
            }
        '
    )"

    if [[ -z "$max_cvss" ]]; then
        max_cvss="null"
        severity="unknown"
    else
        severity="$(severity_from_cvss "$max_cvss")"
    fi

    in_cisa_kev="false"

    while IFS= read -r cve; do
        [[ -z "$cve" ]] && continue

        if is_in_cisa_kev "$cve"; then
            in_cisa_kev="true"
            break
        fi
    done <<< "$cves"

    jq \
        --arg package "$package" \
        --arg installed "$installed_version" \
        --arg candidate "$candidate_version" \
        --arg pocket "$source_pocket" \
        --argjson cves "$cve_json" \
        --argjson max_cvss "$max_cvss" \
        --arg severity "$severity" \
        --argjson kev "$in_cisa_kev" \
        '. += [{
            package: $package,
            installed_version: $installed,
            candidate_version: $candidate,
            source_pocket: $pocket,
            cves: $cves,
            max_cvss: $max_cvss,
            severity: $severity,
            in_cisa_kev: $kev
        }]' \
        "$PACKAGES_JSON" > "${PACKAGES_JSON}.tmp" &&
        mv "${PACKAGES_JSON}.tmp" "$PACKAGES_JSON"

done < "$UPGRADABLE_FILE"

# ---------------------------------------------------------------------------
# Final artifact
# ---------------------------------------------------------------------------

jq \
    --argjson packages "$(cat "$PACKAGES_JSON")" \
    '{
        generated_at: (now | strftime("%Y-%m-%dT%H:%M:%SZ")),
        packages: $packages
    }' > "$OUTPUT_FILE"

log "Vulnerability inventory written to:"
log "$OUTPUT_FILE"

log "Vulnerable packages: $(jq '.packages | length' "$OUTPUT_FILE")"

printf '%s\n' "Inventory complete."
printf '%s\n' "Output: $OUTPUT_FILE"
```
