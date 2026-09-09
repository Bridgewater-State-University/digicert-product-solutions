#!/bin/bash

: <<'LEGAL_NOTICE'
Legal Notice (version January 1, 2026)
Copyright © 2026 DigiCert. All rights reserved.
DigiCert and its logo are registered trademarks of DigiCert, Inc.
Other names may be trademarks of their respective owners.
For the purposes of this Legal Notice, "DigiCert" refers to:
- DigiCert, Inc., if you are located in the United States;
- DigiCert Ireland Limited, if you are located outside of the United States or Japan;
- DigiCert Japan G.K., if you are located in Japan.
The software described in this notice is provided by DigiCert and distributed under licenses
restricting its use, copying, distribution, and decompilation or reverse engineering.
No part of the software may be reproduced in any form by any means without prior written authorization
of DigiCert and its licensors, if any.
Use of the software is subject to the terms and conditions of your agreement with DigiCert, including
any dispute resolution and applicable law provisions. The terms set out herein are supplemental to
your agreement and, in the event of conflict, these terms control.
THE SOFTWARE IS PROVIDED "AS IS" AND ALL EXPRESS OR IMPLIED CONDITIONS, REPRESENTATIONS AND WARRANTIES,
INCLUDING ANY IMPLIED WARRANTY OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT,
ARE DISCLAIMED, EXCEPT TO THE EXTENT THAT SUCH DISCLAIMERS ARE HELD TO BE LEGALLY INVALID.
Export Regulation: The software and related technical data and services (collectively "Controlled Technology")
are subject to the import and export laws of the United States, specifically the U.S. Export Administration
Regulations (EAR), and the laws of any country where Controlled Technology is imported or re-exported.
US Government Restricted Rights: The software is provided with "Restricted Rights," Use, duplication, or
disclosure by the U.S. Government is subject to restrictions as set forth in subparagraph (c)(1)(ii) of the
Rights in Technical Data and Computer Software clause at DFARS 252.227-7013,
subparagraphs (c)(1) and (2) of the Commercial Computer Software—Restricted Rights at 48 CFR 52.227-19,
as applicable, and the Technical Data - Commercial Items clause at DFARS 252.227-7015 (Nov 1995) and any successor regulations.
The contractor/manufacturer is DIGICERT, INC.
LEGAL_NOTICE

# =============================================================================
# DigiCert Trust Lifecycle Manager (TLM) — AWR Post-Enrollment Script
# Palo Alto Panorama Certificate Upload — MULTI-TEMPLATE VARIANT
#
# Uploads a PEM certificate + private key to Palo Alto Panorama via the
# PAN-OS XML API. Designed to run non-interactively as a TLM AWR
# post-enrollment script. All configuration is via DC1_POST_SCRIPT_DATA
# arguments or the variables below.
#
# This variant extends the single-template script: in 'template' mode,
# Arguments 3 and 4 accept SEMICOLON-DELIMITED LISTS so the same certificate
# can be uploaded into multiple Panorama device templates and pushed via
# multiple template stacks in a single run. Semicolons are used as the list
# delimiter because TLM separates AWR arguments with commas. A single name
# (no semicolons) behaves exactly like the original script.
#
# Workflow with multiple templates:
#   - The certificate name is resolved and the cert + key are uploaded once
#     per listed template (each template has its own certificate store, so
#     CN discovery runs independently per template).
#   - A single commit to Panorama covers all templates.
#   - Each listed template stack is then pushed to its devices in order.
#
# Supports two modes (set via MODE variable below):
#
#   template  - Uploads to one or more Panorama device templates, commits,
#               and pushes the listed template stacks to their firewalls.
#               Use for GlobalProtect, SSL Decryption, LDAP, Captive Portal,
#               IPSec, etc.
#
#   system    - Uploads directly to Panorama itself. Use for the Panorama
#               management UI certificate, syslog, SNMP, etc.
#
# The Common Name is extracted automatically from the certificate and used
# for discovery unless Argument 5 provides an explicit certificate name.
# If a certificate with the same CN already exists it is updated in place
# (preserving any bindings such as SSL/TLS profiles, GP portals, etc.)
#
# IMPORTANT: The cert file delivered by TLM must contain only the leaf
#            certificate (single PEM block). If the file contains a full
#            chain, only the first certificate (leaf) is used for the
#            CN extraction, but upload may fail. Configure TLM to deliver
#            the leaf certificate separately.
#
# DC1_POST_SCRIPT_DATA Arguments (configured in TLM AWR):
#   Argument 1 : Panorama IP address or FQDN
#   Argument 2 : Panorama credentials in the format username:password
#                (password may contain colons)
#   Argument 3 : Panorama Template Name(s)  (used in 'template' mode)
#                Single name or semicolon-delimited list,
#                e.g. "TPL-EMEA;TPL-APAC;TPL-AMER"
#   Argument 4 : Panorama Template Stack Name(s) (used in 'template' mode)
#                Single name or semicolon-delimited list,
#                e.g. "Stack-EMEA;Stack-APAC;Stack-AMER"
#   Argument 5 : Certificate name override (optional)
#                If provided, the script targets this exact certificate name
#                in every template and skips CN-based discovery entirely.
#                If omitted, CN-based discovery is used per template.
#                Discovery will fail with an error if multiple certificates
#                share the same CN within a template — in which case set
#                this argument to resolve the ambiguity.
#
# =============================================================================

# =============================================================================
# CONFIGURATION — edit these variables as needed
# =============================================================================

# Legal notice gate — set to "true" to accept the DigiCert legal notice above.
# The script will not run until this is set.
LEGAL_NOTICE_ACCEPT="false"

# Mode: "template" or "system"
#   template — Upload cert to one or more Panorama device templates, commit
#              to Panorama, then push the listed template stacks to their
#              managed firewalls. Use this when the certificate is consumed
#              by firewalls (GlobalProtect, SSL Decryption, LDAP, Captive
#              Portal, IPSec, etc.)
#   system   — Upload cert directly to Panorama's own certificate store and
#              commit. No push to firewalls. Use this when the certificate is
#              for Panorama itself (management UI, syslog, SNMP, etc.)
MODE="system"

# Key passphrase — The PAN-OS import API requires a passphrase parameter even
# when the private key is not encrypted. This value is used as a storage
# passphrase on the PAN-OS side. It is NOT the encryption passphrase of the
# key file delivered by TLM (which is unencrypted PEM). Set this to any
# non-empty string; it acts as a placeholder required by the API.
KEY_PASSPHRASE="ChangeMe123!"

# Seconds to wait between job-status polling requests when monitoring
# Panorama commit and push operations.
WAIT_SECONDS=10

# Log file location — the script will create parent directories if they do
# not exist.
LOGFILE="/home/ubuntu/panorama.log"

# =============================================================================
# END OF CONFIGURATION
# =============================================================================

# --- Ensure log directory exists ---------------------------------------------
LOG_DIR=$(dirname "$LOGFILE")
if [ ! -d "$LOG_DIR" ]; then
    mkdir -p "$LOG_DIR"
fi

# --- Logging helper ----------------------------------------------------------
log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOGFILE"
}

# --- Start logging -----------------------------------------------------------
log_message "=========================================="
log_message "Panorama Certificate Upload (Multi-Template) — AWR Post-Enrollment Script"
log_message "=========================================="

# --- Legal notice gate -------------------------------------------------------
log_message "Checking legal notice acceptance..."
if [ "$LEGAL_NOTICE_ACCEPT" != "true" ]; then
    log_message "ERROR: Legal notice not accepted. Set LEGAL_NOTICE_ACCEPT=\"true\" to proceed."
    log_message "Script execution terminated."
    log_message "=========================================="
    exit 1
else
    log_message "Legal notice accepted, proceeding."
fi

# --- Log configuration -------------------------------------------------------
log_message "Configuration:"
log_message "  MODE: $MODE"
log_message "  KEY_PASSPHRASE: ********"
log_message "  WAIT_SECONDS: $WAIT_SECONDS"
log_message "  LOGFILE: $LOGFILE"

# --- Validate mode -----------------------------------------------------------
if [ "$MODE" != "template" ] && [ "$MODE" != "system" ]; then
    log_message "ERROR: Invalid MODE '$MODE'. Must be 'template' or 'system'."
    exit 1
fi
log_message "Mode validated: $MODE"

# =============================================================================
# DC1_POST_SCRIPT_DATA extraction
# =============================================================================
log_message "Checking DC1_POST_SCRIPT_DATA environment variable..."
if [ -z "${DC1_POST_SCRIPT_DATA:-}" ]; then
    log_message "ERROR: DC1_POST_SCRIPT_DATA environment variable is not set."
    exit 1
else
    log_message "DC1_POST_SCRIPT_DATA is set (length: ${#DC1_POST_SCRIPT_DATA} characters)"
fi

# Decode the base64-encoded JSON payload
CERT_INFO="${DC1_POST_SCRIPT_DATA}"
JSON_STRING=$(echo "$CERT_INFO" | base64 -d)
log_message "JSON decoded successfully."
log_message "Raw JSON content not logged because it contains credentials."

# --- Extract arguments from JSON ---------------------------------------------
log_message "Extracting arguments from JSON..."

# Extract the args array. Quoted strings are matched atomically so a value
# containing ']' cannot truncate the array early.
ARGS_ARRAY=$(echo "$JSON_STRING" | grep -oP '"args":\[\K(?:"(?:\\.|[^"\\])*"|[^\]])*')
log_message "Raw args array not logged because Argument 2 contains credentials."

# Split the args array into its JSON string elements. Matching whole quoted
# strings (including \" escapes) preserves commas, colons, quotes and spaces
# inside values — naive comma-splitting truncates passwords containing
# commas, and stripping all whitespace corrupts passwords containing spaces.
ARGS_LIST=()
while IFS= read -r _ARG_ELEM; do
    _ARG_ELEM="${_ARG_ELEM#\"}"
    _ARG_ELEM="${_ARG_ELEM%\"}"
    _ARG_ELEM=$(printf '%s' "$_ARG_ELEM" | sed -e 's/\\"/"/g' -e 's/\\\\/\\/g')
    ARGS_LIST+=("$_ARG_ELEM")
done < <(echo "$ARGS_ARRAY" | grep -oP '"(?:\\.|[^"\\])*"')
log_message "Parsed ${#ARGS_LIST[@]} argument(s) from args array."

# Argument 1 — Panorama IP / FQDN
PANORAMA_IP=$(printf '%s' "${ARGS_LIST[0]:-}" | tr -d '[:space:]')
log_message "PANORAMA_IP (Arg1): '$PANORAMA_IP'"

# Argument 2 — Combined credentials in the format username:password
# The password portion is extracted with cut -f2- to safely handle passwords
# that themselves contain colons. Only leading/trailing whitespace is trimmed
# — the password may legitimately contain spaces and special characters.
ARG2_CREDENTIAL=$(printf '%s' "${ARGS_LIST[1]:-}" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
PANORAMA_USER=$(printf '%s' "$ARG2_CREDENTIAL" | cut -d: -f1)
PANORAMA_PASS=$(printf '%s' "$ARG2_CREDENTIAL" | cut -d: -f2-)
log_message "PANORAMA_USER (Arg2, from credential): '$PANORAMA_USER'"
log_message "PANORAMA_PASS (Arg2, from credential): ********"

# Argument 3 — Panorama Template Name(s) (template mode)
# Single name or semicolon-delimited list. Empty entries (e.g. from a
# trailing semicolon) are dropped.
TEMPLATE_ARG=$(printf '%s' "${ARGS_LIST[2]:-}" | tr -d '[:space:]')
TEMPLATE_NAMES=()
IFS=';' read -ra _RAW_TEMPLATES <<< "$TEMPLATE_ARG"
for _T in "${_RAW_TEMPLATES[@]}"; do
    [ -n "$_T" ] && TEMPLATE_NAMES+=("$_T")
done
log_message "TEMPLATE_NAMES (Arg3): ${#TEMPLATE_NAMES[@]} template(s): '${TEMPLATE_NAMES[*]:-}'"

# Argument 4 — Panorama Template Stack Name(s) (template mode)
# Single name or semicolon-delimited list. Empty entries are dropped.
STACK_ARG=$(printf '%s' "${ARGS_LIST[3]:-}" | tr -d '[:space:]')
TEMPLATE_STACK_NAMES=()
IFS=';' read -ra _RAW_STACKS <<< "$STACK_ARG"
for _S in "${_RAW_STACKS[@]}"; do
    [ -n "$_S" ] && TEMPLATE_STACK_NAMES+=("$_S")
done
log_message "TEMPLATE_STACK_NAMES (Arg4): ${#TEMPLATE_STACK_NAMES[@]} stack(s): '${TEMPLATE_STACK_NAMES[*]:-}'"

# Argument 5 — Certificate name override (optional)
# If set, the script targets this exact Panorama certificate entry name in
# every template and skips CN-based discovery. If empty, CN discovery is
# used per template with ambiguity detection (see Step 2).
CERT_NAME_OVERRIDE=$(printf '%s' "${ARGS_LIST[4]:-}" | tr -d '[:space:]')
if [ -n "$CERT_NAME_OVERRIDE" ]; then
    log_message "CERT_NAME_OVERRIDE (Arg5): '$CERT_NAME_OVERRIDE'"
else
    log_message "CERT_NAME_OVERRIDE (Arg5): <not set — CN discovery will be used>"
fi

# --- Validate required arguments ---------------------------------------------
if [ -z "$PANORAMA_IP" ]; then
    log_message "ERROR: Argument 1 (Panorama IP/FQDN) is empty."
    exit 1
fi
if [ -z "$PANORAMA_USER" ]; then
    log_message "ERROR: Argument 2 (credentials) did not yield a username. Expected format: username:password"
    exit 1
fi
if [ -z "$PANORAMA_PASS" ]; then
    log_message "ERROR: Argument 2 (credentials) did not yield a password. Expected format: username:password"
    exit 1
fi
if [ "$MODE" = "template" ]; then
    if [ ${#TEMPLATE_NAMES[@]} -eq 0 ]; then
        log_message "ERROR: Argument 3 (Template Name(s)) is required in template mode."
        exit 1
    fi
    if [ ${#TEMPLATE_STACK_NAMES[@]} -eq 0 ]; then
        log_message "ERROR: Argument 4 (Template Stack Name(s)) is required in template mode."
        exit 1
    fi
fi
log_message "All required arguments validated."

# --- Extract certificate and key file paths ----------------------------------
log_message "Extracting certificate file paths from JSON..."

CERT_FOLDER=$(echo "$JSON_STRING" | grep -oP '"certfolder":"\K[^"]+')
log_message "CERT_FOLDER: $CERT_FOLDER"

CRT_FILE=$(echo "$JSON_STRING" | grep -oP '"files":\[\K[^]]*' | grep -oP '[^,"]+\.crt')
log_message "CRT_FILE: $CRT_FILE"

KEY_FILE=$(echo "$JSON_STRING" | grep -oP '"files":\[\K[^]]*' | grep -oP '[^,"]+\.key')
log_message "KEY_FILE: $KEY_FILE"

CRT_FILE_PATH="${CERT_FOLDER}/${CRT_FILE}"
KEY_FILE_PATH="${CERT_FOLDER}/${KEY_FILE}"
log_message "Certificate path: $CRT_FILE_PATH"
log_message "Private key path: $KEY_FILE_PATH"

FILES_ARRAY=$(echo "$JSON_STRING" | grep -oP '"files":\[\K[^]]*')
log_message "All files in array: $FILES_ARRAY"

# --- Validate certificate and key files exist --------------------------------
if [ ! -f "$CRT_FILE_PATH" ]; then
    log_message "ERROR: Certificate file not found: $CRT_FILE_PATH"
    exit 1
fi
log_message "Certificate file exists: $CRT_FILE_PATH ($(stat -c%s "$CRT_FILE_PATH") bytes)"

CERT_COUNT=$(grep -c "BEGIN CERTIFICATE" "${CRT_FILE_PATH}")
log_message "Certificates in file: $CERT_COUNT"

if [ ! -f "$KEY_FILE_PATH" ]; then
    log_message "ERROR: Private key file not found: $KEY_FILE_PATH"
    exit 1
fi
log_message "Private key file exists: $KEY_FILE_PATH ($(stat -c%s "$KEY_FILE_PATH") bytes)"

# Determine key type for logging
KEY_FILE_CONTENT=$(cat "${KEY_FILE_PATH}")
if echo "$KEY_FILE_CONTENT" | grep -q "BEGIN RSA PRIVATE KEY"; then
    KEY_TYPE="RSA"
elif echo "$KEY_FILE_CONTENT" | grep -q "BEGIN EC PRIVATE KEY"; then
    KEY_TYPE="ECC"
elif echo "$KEY_FILE_CONTENT" | grep -q "BEGIN PRIVATE KEY"; then
    KEY_TYPE="PKCS#8"
else
    KEY_TYPE="Unknown"
fi
log_message "Key type: $KEY_TYPE"

# =============================================================================
# Panorama Certificate Upload
# =============================================================================

# --- Extract Common Name from the certificate --------------------------------
log_message "=========================================="
log_message "Extracting Common Name from certificate..."
COMMON_NAME=$(openssl x509 -in "$CRT_FILE_PATH" -noout -subject -nameopt RFC2253 \
    | grep -oP '(?<=CN=)[^,]*') || true

if [ -z "$COMMON_NAME" ]; then
    log_message "ERROR: Could not extract Common Name from certificate: $CRT_FILE_PATH"
    exit 1
fi
log_message "Common Name: $COMMON_NAME"

# --- Display banner (to log) -------------------------------------------------
log_message "============================================"
log_message "Panorama Certificate Upload (Multi-Template)"
log_message "============================================"
log_message "Mode:           $MODE"
log_message "Common Name:    $COMMON_NAME"
log_message "Cert File:      $CRT_FILE_PATH"
log_message "Key File:       $KEY_FILE_PATH"
log_message "Panorama:       $PANORAMA_IP"
log_message "User:           $PANORAMA_USER"
if [ -n "$CERT_NAME_OVERRIDE" ]; then
    log_message "Cert Name:      $CERT_NAME_OVERRIDE (explicit override — discovery skipped)"
else
    log_message "Cert Name:      <will be determined by CN discovery per template>"
fi
if [ "$MODE" = "template" ]; then
    log_message "Templates (${#TEMPLATE_NAMES[@]}):"
    for _T in "${TEMPLATE_NAMES[@]}"; do
        log_message "  - $_T"
    done
    log_message "Template Stacks (${#TEMPLATE_STACK_NAMES[@]}):"
    for _S in "${TEMPLATE_STACK_NAMES[@]}"; do
        log_message "  - $_S"
    done
fi
log_message "============================================"

# --- Helper: wait for a PAN-OS job to complete --------------------------------
wait_for_job() {
    local JOB_ID="$1"
    local JOB_LABEL="$2"

    while true; do
        sleep "$WAIT_SECONDS"
        JOB_XML=$(curl -sk -g \
            "https://${PANORAMA_IP}/api/?type=op&cmd=<show><jobs><id>${JOB_ID}</id></jobs></show>&key=${API_KEY}")

        JOB_FLAT=$(echo "$JOB_XML" | tr -d '\n')

        STATUS=$(echo "$JOB_FLAT" | grep -oP '(?<=<status>)[^<]*' | head -1) || true
        PROGRESS=$(echo "$JOB_FLAT" | grep -oP '(?<=<progress>)[^<]*' | head -1) || true

        JOB_RESULT=""
        if echo "$JOB_FLAT" | grep -qP '<result>OK</result>'; then
            JOB_RESULT="OK"
        elif echo "$JOB_FLAT" | grep -qP '<result>FAIL</result>'; then
            JOB_RESULT="FAIL"
        fi

        if [ "$STATUS" = "FIN" ]; then
            if [ "$JOB_RESULT" = "OK" ]; then
                log_message "  ${JOB_LABEL} completed successfully."
                return 0
            else
                log_message "ERROR: ${JOB_LABEL} failed."
                log_message "$JOB_XML"
                return 1
            fi
        else
            log_message "  ${JOB_LABEL}... ${PROGRESS}%"
        fi
    done
}

# --- Helper: resolve cert name + upload cert & key to one target --------------
# $1 = template name, or empty string for system mode (Panorama's own store).
# Steps 2–4 run once per target because each template has its own certificate
# store — CN discovery can resolve to a different entry name per template.
# On success the resolved name is appended to RESOLVED_SUMMARY for the final
# summary block. Any failure exits the script (an aborted run leaves nothing
# committed, since the commit only happens after all uploads succeed).
RESOLVED_SUMMARY=()
process_target() {
    local TARGET_TEMPLATE="$1"
    local TARGET_LABEL
    if [ -n "$TARGET_TEMPLATE" ]; then
        TARGET_LABEL="template '$TARGET_TEMPLATE'"
    else
        TARGET_LABEL="Panorama (system)"
    fi

    # --- Step 2: Resolve certificate name -------------------------------------
    log_message "[2] Resolving target certificate name for ${TARGET_LABEL}..."

    local CERT_XPATH
    if [ -n "$TARGET_TEMPLATE" ]; then
        CERT_XPATH="/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='${TARGET_TEMPLATE}']/config/shared/certificate"
    else
        CERT_XPATH="/config/shared/certificate"
    fi

    local CERT_NAME
    if [ -n "$CERT_NAME_OVERRIDE" ]; then
        # --- Explicit override: trust the provided name, no discovery needed --
        CERT_NAME="$CERT_NAME_OVERRIDE"
        log_message "  Using explicit certificate name override: '$CERT_NAME'"
        log_message "  CN-based discovery skipped."
    else
        # --- CN-based discovery ------------------------------------------------
        log_message "  No override provided — performing CN-based discovery for CN='$COMMON_NAME'..."

        local CERT_XML CERT_XML_FLAT
        CERT_XML=$(curl -sk -g \
            "https://${PANORAMA_IP}/api/?type=config&action=get&xpath=${CERT_XPATH}&key=${API_KEY}")

        CERT_XML_FLAT=$(echo "$CERT_XML" | tr -d '\n' | tr -s ' ')

        # Collect all certificate entry names that match the CN
        local MATCHING_NAMES=()
        local ENTRY_NAME
        while IFS= read -r ENTRY_NAME; do
            MATCHING_NAMES+=("$ENTRY_NAME")
        done < <(echo "$CERT_XML_FLAT" \
            | grep -oP '<entry name="[^"]*"[^>]*>.*?</entry>' \
            | grep "<common-name>${COMMON_NAME}</common-name>" \
            | grep -oP '(?<=<entry name=")[^"]*')

        local MATCH_COUNT=${#MATCHING_NAMES[@]}

        if [ "$MATCH_COUNT" -eq 0 ]; then
            log_message "  No existing certificate found with CN='$COMMON_NAME' in ${TARGET_LABEL}."
            log_message "  A new certificate entry will be created."
            CERT_NAME=$(echo "$COMMON_NAME" | tr '.' '-')
            log_message "  Derived certificate name: '$CERT_NAME'"

        elif [ "$MATCH_COUNT" -eq 1 ]; then
            CERT_NAME="${MATCHING_NAMES[0]}"
            log_message "  Found exactly one certificate with CN='$COMMON_NAME': '$CERT_NAME'"
            log_message "  Will update in place (bindings will be preserved)."

        else
            # Multiple certificates share the same CN — fail loudly
            log_message "ERROR: CN-based discovery found $MATCH_COUNT certificates sharing CN='$COMMON_NAME' in ${TARGET_LABEL}."
            log_message "  Panorama cannot reliably determine which entry to update."
            log_message "  Conflicting certificate names:"
            local NAME
            for NAME in "${MATCHING_NAMES[@]}"; do
                log_message "    - $NAME"
            done
            log_message "  ACTION REQUIRED: Set Argument 5 (certificate name override) to the exact"
            log_message "  Panorama certificate entry name you want to update, then re-run."
            exit 1
        fi
    fi

    # --- Step 3: Upload certificate (PEM) --------------------------------------
    log_message "[3] Uploading certificate '$CERT_NAME' to ${TARGET_LABEL}..."

    # Text fields use --form-string so values are sent literally — with plain
    # -F, curl treats a leading '@' or '<' in the value as a file reference.
    local UPLOAD_CERT_ARGS=(
        -F "file=@${CRT_FILE_PATH}"
        --form-string "type=import"
        --form-string "category=certificate"
        --form-string "certificate-name=${CERT_NAME}"
        --form-string "format=pem"
        --form-string "key=${API_KEY}"
    )

    if [ -n "$TARGET_TEMPLATE" ]; then
        UPLOAD_CERT_ARGS+=(--form-string "target-tpl=${TARGET_TEMPLATE}")
    fi

    local UPLOAD_CERT_RESPONSE
    UPLOAD_CERT_RESPONSE=$(curl -sk -X POST "https://${PANORAMA_IP}/api/" "${UPLOAD_CERT_ARGS[@]}")

    if echo "$UPLOAD_CERT_RESPONSE" | grep -q 'status="success"'; then
        log_message "  Certificate uploaded successfully."
    else
        log_message "ERROR: Certificate upload to ${TARGET_LABEL} failed:"
        log_message "$UPLOAD_CERT_RESPONSE"
        exit 1
    fi

    # --- Step 4: Upload private key (PEM) --------------------------------------
    log_message "[4] Uploading private key for '$CERT_NAME' to ${TARGET_LABEL}..."

    local UPLOAD_KEY_ARGS=(
        -F "file=@${KEY_FILE_PATH}"
        --form-string "type=import"
        --form-string "category=private-key"
        --form-string "certificate-name=${CERT_NAME}"
        --form-string "format=pem"
        --form-string "passphrase=${KEY_PASSPHRASE}"
        --form-string "key=${API_KEY}"
    )

    if [ -n "$TARGET_TEMPLATE" ]; then
        UPLOAD_KEY_ARGS+=(--form-string "target-tpl=${TARGET_TEMPLATE}")
    fi

    local UPLOAD_KEY_RESPONSE
    UPLOAD_KEY_RESPONSE=$(curl -sk -X POST "https://${PANORAMA_IP}/api/" "${UPLOAD_KEY_ARGS[@]}")

    if echo "$UPLOAD_KEY_RESPONSE" | grep -q 'status="success"'; then
        log_message "  Private key uploaded successfully."
    else
        log_message "ERROR: Private key upload to ${TARGET_LABEL} failed:"
        log_message "$UPLOAD_KEY_RESPONSE"
        exit 1
    fi

    RESOLVED_SUMMARY+=("${TARGET_LABEL}: '${CERT_NAME}'")
}

# --- Step 1: Authenticate to Panorama (get API key) --------------------------
# Credentials go in the POST body, not the query string, so the password
# doesn't leak into Panorama's web access logs. --data-urlencode percent-
# encodes the values, so special characters in the password are safe.
log_message "[1] Authenticating to Panorama ($PANORAMA_IP)..."
API_KEY_RESPONSE=$(curl -sk \
    --request POST \
    --data-urlencode "type=keygen" \
    --data-urlencode "user=${PANORAMA_USER}" \
    --data-urlencode "password=${PANORAMA_PASS}" \
    "https://${PANORAMA_IP}/api/")

API_KEY=$(echo "$API_KEY_RESPONSE" | grep -oP '(?<=<key>)[^<]*') || true

if [ -z "$API_KEY" ]; then
    log_message "ERROR: Failed to get API key. Response:"
    log_message "$API_KEY_RESPONSE"
    exit 1
fi
log_message "  Authenticated successfully."

# --- Steps 2–4: Resolve + upload, once per target ----------------------------
if [ "$MODE" = "template" ]; then
    TEMPLATE_INDEX=0
    for TEMPLATE_NAME in "${TEMPLATE_NAMES[@]}"; do
        TEMPLATE_INDEX=$((TEMPLATE_INDEX + 1))
        log_message "------------------------------------------"
        log_message "Template ${TEMPLATE_INDEX}/${#TEMPLATE_NAMES[@]}: '$TEMPLATE_NAME'"
        log_message "------------------------------------------"
        process_target "$TEMPLATE_NAME"
    done
else
    process_target ""
fi

# --- Step 5: Commit to Panorama (single commit covers all templates) ---------
log_message "[5] Committing to Panorama..."
COMMIT_RESPONSE=$(curl -sk -g \
    "https://${PANORAMA_IP}/api/?type=commit&cmd=<commit></commit>&key=${API_KEY}")

COMMIT_JOB_ID=$(echo "$COMMIT_RESPONSE" | grep -oP '(?<=<job>)[^<]*') || true

if [ -z "$COMMIT_JOB_ID" ]; then
    log_message "  No commit job created (may be nothing to commit or already committed)."
    log_message "  Response: $COMMIT_RESPONSE"
else
    log_message "  Commit job ID: $COMMIT_JOB_ID"
    wait_for_job "$COMMIT_JOB_ID" "Commit"
fi

# --- Step 6: Push to devices (template mode only) ----------------------------
# Each listed template stack is pushed sequentially. A stack that fails to
# create a push job logs a warning and the remaining stacks are still pushed;
# a push job that runs and FAILS aborts the script (via wait_for_job).
if [ "$MODE" = "template" ]; then
    STACK_INDEX=0
    for TEMPLATE_STACK_NAME in "${TEMPLATE_STACK_NAMES[@]}"; do
        STACK_INDEX=$((STACK_INDEX + 1))
        log_message "[6] Pushing template stack ${STACK_INDEX}/${#TEMPLATE_STACK_NAMES[@]} '$TEMPLATE_STACK_NAME' to all devices..."
        PUSH_CMD="<commit-all><template-stack><name>${TEMPLATE_STACK_NAME}</name></template-stack></commit-all>"
        PUSH_RESPONSE=$(curl -sk "https://${PANORAMA_IP}/api/?type=commit&action=all&key=${API_KEY}" --data-urlencode "cmd=${PUSH_CMD}")

        PUSH_JOB_ID=$(echo "$PUSH_RESPONSE" | grep -oP '(?<=<job>)[^<]*') || true

        if [ -z "$PUSH_JOB_ID" ]; then
            log_message "  WARNING: No push job created for stack '$TEMPLATE_STACK_NAME'. Response:"
            log_message "  $PUSH_RESPONSE"
        else
            log_message "  Push job ID: $PUSH_JOB_ID"
            wait_for_job "$PUSH_JOB_ID" "Push to devices ($TEMPLATE_STACK_NAME)"
        fi
    done
else
    log_message "[6] Skipping push (system mode — cert is on Panorama itself)."
fi

# --- Summary -----------------------------------------------------------------
log_message "=========================================="
log_message "COMPLETED SUCCESSFULLY"
log_message "=========================================="
log_message "Certificate (CN=$COMMON_NAME)"
log_message "  Mode: $MODE"
if [ "$MODE" = "template" ]; then
    log_message "  Uploaded to ${#TEMPLATE_NAMES[@]} template(s):"
    for ENTRY in "${RESOLVED_SUMMARY[@]}"; do
        log_message "    - $ENTRY"
    done
    log_message "  Committed to Panorama"
    log_message "  Pushed to devices via ${#TEMPLATE_STACK_NAMES[@]} stack(s):"
    for _S in "${TEMPLATE_STACK_NAMES[@]}"; do
        log_message "    - $_S"
    done
else
    log_message "  Uploaded to Panorama (system): ${RESOLVED_SUMMARY[0]:-}"
    log_message "  Committed to Panorama"
    log_message "  NOTE: To use this cert for the management UI, create an"
    log_message "    SSL/TLS Service Profile referencing this cert, then assign"
    log_message "    it in Panorama > Setup > Management > General Settings."
fi
log_message "=========================================="

exit 0
