#!/bin/bash
#
# Rapax SNMP Trap Handler
# =======================
#
# Custom traphandle script for snmptrapd that formats trap data
# into a single JSON line for efficient processing.
#
# Output format (logged to syslog with 'snmptrap' tag):
#   {"source":"<ip>","trap_oid":"<oid>","varbinds":{...},"timestamp":"<iso>"}
#
# Installation:
#   1. Copy to /usr/local/bin/rapax-traphandle.sh
#   2. chmod +x /usr/local/bin/rapax-traphandle.sh
#   3. Configure snmptrapd.conf:
#      traphandle default /usr/local/bin/rapax-traphandle.sh
#

DEBUGLOG="/tmp/rapax-traphandle.log"
debug() { { echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') $1" >> "$DEBUGLOG"; } 2>/dev/null; }

# Trim debug log in place when it grows past 100 lines. Truncate-in-place
# (`: > FILE`) preserves the inode/owner/mode, unlike `tail|mv` which would
# transfer ownership to whoever ran the script and lock other users out.
{
    if [ -s "$DEBUGLOG" ] && [ "$(wc -l < "$DEBUGLOG" 2>/dev/null || echo 0)" -gt 100 ]; then
        _keep=$(tail -100 "$DEBUGLOG" 2>/dev/null)
        : > "$DEBUGLOG"
        printf '%s\n' "$_keep" >> "$DEBUGLOG"
    fi
} 2>/dev/null

debug "--- traphandle invoked ---"

# Read all input lines from snmptrapd
declare -a LINES
while IFS= read -r line; do
    LINES+=("$line")
done

# Parse the trap data
# Line 0: hostname (often <UNKNOWN>)
# Line 1: transport info (UDP: [source]:port->[dest]:port)
# Line 2+: OID value pairs

HOSTNAME="${LINES[0]:-unknown}"
TRANSPORT="${LINES[1]:-}"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%S.%3NZ")

# Extract source IP from transport line
# Format: UDP: [192.168.1.1]:12345->[192.168.2.1]:162
SOURCE_IP="unknown"
if [[ "$TRANSPORT" =~ UDP:\ \[([0-9\.]+)\]: ]]; then
    SOURCE_IP="${BASH_REMATCH[1]}"
fi

# Initialize variables
TRAP_OID=""
declare -A VARBINDS

# Process OID/value pairs (lines 2+)
for ((i=2; i<${#LINES[@]}; i++)); do
    line="${LINES[$i]}"

    # Skip empty lines
    [[ -z "$line" ]] && continue

    # Parse OID and value. Three OID prefix forms appear in snmptrapd output:
    #   `iso.3.6.1...` (default with MIBs loaded; `iso` is the symbolic form of `1`)
    #   `.1.3.6.1...`  (numeric with `-On` / `printNumericOids 1`)
    #   `1.3.6.1...`   (no prefix)
    # The regex captures the prefix and digits separately so we can normalize.
    if [[ "$line" =~ ^(iso\.|\.)?([0-9][0-9\.]*)[[:space:]]+(.*)$ ]]; then
        _prefix="${BASH_REMATCH[1]}"
        OID="${BASH_REMATCH[2]}"
        VALUE="${BASH_REMATCH[3]}"
        # Normalize: `iso.` is the symbolic form of `1.` — prepend it.
        # Leading dot was already excluded from the digits group; nothing to do.
        [[ "$_prefix" == "iso." ]] && OID="1.$OID"

        # Strip a `= ` separator and known type prefixes that snmptrapd emits
        # (e.g. `OID: .1.3.6...`, `STRING: "foo"`, `INTEGER: 42`).
        VALUE="${VALUE#= }"
        for prefix in 'OID: ' 'STRING: ' 'INTEGER: ' 'Counter32: ' 'Counter64: ' \
                      'Gauge32: ' 'Timeticks: ' 'IpAddress: ' 'Hex-STRING: ' \
                      'OCTET STRING: ' 'BITS: '; do
            VALUE="${VALUE#${prefix}}"
        done
        VALUE="${VALUE%\"}"
        VALUE="${VALUE#\"}"

        # Check if this is the snmpTrapOID (1.3.6.1.6.3.1.1.4.1.0)
        if [[ "$OID" == "1.3.6.1.6.3.1.1.4.1.0" ]]; then
            # Extract trap OID from value (may have iso. or leading-dot prefix)
            if [[ "$VALUE" =~ ^(iso\.|\.)?([0-9][0-9\.]*)$ ]]; then
                _vprefix="${BASH_REMATCH[1]}"
                TRAP_OID="${BASH_REMATCH[2]}"
                [[ "$_vprefix" == "iso." ]] && TRAP_OID="1.$TRAP_OID"
            fi
        else
            VARBINDS["$OID"]="$VALUE"
        fi
    fi
done

debug "trap_oid=$TRAP_OID varbind_count=${#VARBINDS[@]}"

# Build varbinds JSON object
VARBINDS_JSON="{"
first=true
for oid in "${!VARBINDS[@]}"; do
    value="${VARBINDS[$oid]}"
    # Escape special JSON characters in value
    value="${value//\\/\\\\}"
    value="${value//\"/\\\"}"
    value="${value//$'\n'/\\n}"
    value="${value//$'\r'/\\r}"
    value="${value//$'\t'/\\t}"

    if [ "$first" = true ]; then
        first=false
    else
        VARBINDS_JSON+=","
    fi
    VARBINDS_JSON+="\"$oid\":\"$value\""
done
VARBINDS_JSON+="}"

# Build final JSON line
JSON_OUTPUT="{\"timestamp\":\"$TIMESTAMP\",\"source\":\"$SOURCE_IP\",\"trap_oid\":\"$TRAP_OID\",\"varbinds\":$VARBINDS_JSON}"

debug "json=$JSON_OUTPUT"

# Log to syslog with snmptrap tag
logger -t snmptrap "$JSON_OUTPUT"
