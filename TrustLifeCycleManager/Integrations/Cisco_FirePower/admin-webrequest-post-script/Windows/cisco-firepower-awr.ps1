<#
.SYNOPSIS
    DigiCert TLM Agent Certificate Processing Script (CRT/KEY Format) - Cisco Firepower Management Center (FMC)
.DESCRIPTION
    Admin Web Request (AWR) post-enrollment script for the DigiCert TLM Agent.
    Reads the DC1_POST_SCRIPT_DATA payload, extracts the certificate (.crt) and private key (.key)
    files the agent wrote to disk, authenticates to Cisco Firepower Management Center (FMC) and
    creates or updates an Internal Certificate object via the FMC REST API.

    Follows the standard DigiCert AWR post-enrollment flow (legal-notice gate, payload decoding,
    argument extraction, certificate inspection). The FMC deployment lives in the
    CUSTOM SCRIPT SECTION at the bottom of the file.
.NOTES
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
#>


# Configuration
$LEGAL_NOTICE_ACCEPT = "false"
$LOGFILE = "C:\Program Files\DigiCert\TLM Agent\log\fmc_awr.log"

# ============================================================================
# AWR argument mapping (configure these in the TLM Admin Web Request):
#   $ARGUMENT_1 - FMC username:password  (e.g. admin:P@ssw0rd)
#   $ARGUMENT_2 - FMC hostname or IP     (e.g. fmc.example.com or https://fmc.example.com)
#   $ARGUMENT_3 - Internal Certificate object name to create/update in FMC
# ============================================================================

# Function to log messages with timestamp
function Write-LogMessage {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "[$timestamp] $Message" | Add-Content -Path $LOGFILE -Encoding UTF8
}

# Function to mask a password for log output
function Mask-Password {
    param([string]$Password)
    if ([string]::IsNullOrEmpty($Password)) { return "(empty)" }
    return "********"
}

# Ensure the log directory exists
$logDir = Split-Path -Path $LOGFILE -Parent
if (-not (Test-Path -Path $logDir)) {
    New-Item -ItemType Directory -Path $logDir -Force | Out-Null
}

# Start logging
Write-LogMessage "=========================================="
Write-LogMessage "Starting DC1_POST_SCRIPT_DATA extraction script"
Write-LogMessage "=========================================="

# Check legal notice acceptance
Write-LogMessage "Checking legal notice acceptance..."
if ($LEGAL_NOTICE_ACCEPT -ne "true") {
    Write-LogMessage "ERROR: Legal notice not accepted. Set LEGAL_NOTICE_ACCEPT=`"true`" to proceed."
    Write-LogMessage "Script execution terminated due to legal notice non-acceptance."
    Write-LogMessage "=========================================="
    exit 1
} else {
    Write-LogMessage "Legal notice accepted, proceeding with script execution."
}

# Log initial configuration
Write-LogMessage "Configuration:"
Write-LogMessage "  LEGAL_NOTICE_ACCEPT: $LEGAL_NOTICE_ACCEPT"
Write-LogMessage "  LOGFILE: $LOGFILE"

# Log environment variable check
Write-LogMessage "Checking DC1_POST_SCRIPT_DATA environment variable..."
$CERT_INFO = $env:DC1_POST_SCRIPT_DATA

if ([string]::IsNullOrEmpty($CERT_INFO)) {
    Write-LogMessage "ERROR: DC1_POST_SCRIPT_DATA environment variable is not set"
    exit 1
} else {
    Write-LogMessage "DC1_POST_SCRIPT_DATA is set (length: $($CERT_INFO.Length) characters)"
}

Write-LogMessage "CERT_INFO length: $($CERT_INFO.Length) characters"

# Decode JSON string from Base64
try {
    $JSON_BYTES = [System.Convert]::FromBase64String($CERT_INFO)
    $JSON_STRING = [System.Text.Encoding]::UTF8.GetString($JSON_BYTES)
    Write-LogMessage "JSON_STRING decoded successfully"
} catch {
    Write-LogMessage "ERROR: Failed to decode Base64: $_"
    exit 1
}

# Log the raw JSON for debugging (credentials and passwords masked)
$JSON_FOR_LOG = $JSON_STRING
# Mask the password half of args[0] ("user:password" -> "user:********")
$JSON_FOR_LOG = [regex]::Replace($JSON_FOR_LOG, '("args"\s*:\s*\[\s*")([^":]*):([^"]*)(")', '$1$2:********$4')
# Mask any password-like fields in the payload
$JSON_FOR_LOG = $JSON_FOR_LOG -replace '("password"\s*:\s*")[^"]*(")', '$1********$2'
$JSON_FOR_LOG = $JSON_FOR_LOG -replace '("pfx_password"\s*:\s*")[^"]*(")', '$1********$2'
$JSON_FOR_LOG = $JSON_FOR_LOG -replace '("keystore_password"\s*:\s*")[^"]*(")', '$1********$2'
$JSON_FOR_LOG = $JSON_FOR_LOG -replace '("passphrase"\s*:\s*")[^"]*(")', '$1********$2'

Write-LogMessage "=========================================="
Write-LogMessage "Raw JSON content (credentials masked):"
Write-LogMessage $JSON_FOR_LOG
Write-LogMessage "=========================================="

# Parse JSON
try {
    $JSON_OBJECT = $JSON_STRING | ConvertFrom-Json
    Write-LogMessage "JSON parsed successfully"
} catch {
    Write-LogMessage "ERROR: Failed to parse JSON: $_"
    exit 1
}

# Extract arguments from JSON
Write-LogMessage "Extracting arguments from JSON..."

# Initialize argument variables (this integration uses 3)
$ARGUMENT_1 = ""
$ARGUMENT_2 = ""
$ARGUMENT_3 = ""

# Extract arguments if they exist
if ($JSON_OBJECT.args) {
    $ARGS_ARRAY = @($JSON_OBJECT.args)

    # ARGUMENT_1 carries FMC credentials - mask the password half in the log
    $argsForLog = @($ARGS_ARRAY | ForEach-Object { $_ })
    if ($argsForLog.Count -ge 1 -and "$($argsForLog[0])".Contains(':')) {
        $argsForLog[0] = "$($argsForLog[0])".Substring(0, "$($argsForLog[0])".IndexOf(':')) + ":********"
    }
    Write-LogMessage "Raw args array: $($argsForLog -join ',')"

    if ($ARGS_ARRAY.Count -ge 1) {
        $ARGUMENT_1 = ("$($ARGS_ARRAY[0])" -replace '\s', '').Trim()
        $arg1ForLog = $ARGUMENT_1
        if ($ARGUMENT_1.Contains(':')) {
            $arg1ForLog = $ARGUMENT_1.Substring(0, $ARGUMENT_1.IndexOf(':')) + ":********"
        }
        Write-LogMessage "ARGUMENT_1 extracted: '$arg1ForLog'"
        Write-LogMessage "ARGUMENT_1 length: $($ARGUMENT_1.Length)"
    }
    if ($ARGS_ARRAY.Count -ge 2) {
        $ARGUMENT_2 = ("$($ARGS_ARRAY[1])" -replace '\s', '').Trim()
        Write-LogMessage "ARGUMENT_2 extracted: '$ARGUMENT_2'"
        Write-LogMessage "ARGUMENT_2 length: $($ARGUMENT_2.Length)"
    }
    if ($ARGS_ARRAY.Count -ge 3) {
        $ARGUMENT_3 = ("$($ARGS_ARRAY[2])" -replace '\s', '').Trim()
        Write-LogMessage "ARGUMENT_3 extracted: '$ARGUMENT_3'"
        Write-LogMessage "ARGUMENT_3 length: $($ARGUMENT_3.Length)"
    }
    if ($ARGS_ARRAY.Count -gt 3) {
        Write-LogMessage "NOTE: $($ARGS_ARRAY.Count - 3) additional argument(s) supplied but not used by this integration"
    }
}

# Extract cert folder
$CERT_FOLDER = $JSON_OBJECT.certfolder
Write-LogMessage "Extracted CERT_FOLDER: $CERT_FOLDER"

# Extract the .crt file name
$CRT_FILE = ""
if ($JSON_OBJECT.files) {
    $CRT_FILE = $JSON_OBJECT.files | Where-Object { $_ -match '\.crt$' } | Select-Object -First 1
}
Write-LogMessage "Extracted CRT_FILE: $CRT_FILE"

# Extract the .key file name
$KEY_FILE = ""
if ($JSON_OBJECT.files) {
    $KEY_FILE = $JSON_OBJECT.files | Where-Object { $_ -match '\.key$' } | Select-Object -First 1
}
Write-LogMessage "Extracted KEY_FILE: $KEY_FILE"

# Construct file paths
$CRT_FILE_PATH = Join-Path -Path $CERT_FOLDER -ChildPath $CRT_FILE
$KEY_FILE_PATH = Join-Path -Path $CERT_FOLDER -ChildPath $KEY_FILE

# Extract all files from the files array
$FILES_ARRAY = $JSON_OBJECT.files -join ','
Write-LogMessage "Files array content: $FILES_ARRAY"

# Log summary
Write-LogMessage "=========================================="
Write-LogMessage "EXTRACTION SUMMARY:"
Write-LogMessage "=========================================="
Write-LogMessage "Arguments extracted:"
Write-LogMessage "  Argument 1: $arg1ForLog"
Write-LogMessage "  Argument 2: $ARGUMENT_2"
Write-LogMessage "  Argument 3: $ARGUMENT_3"
Write-LogMessage ""
Write-LogMessage "Certificate information:"
Write-LogMessage "  Certificate folder: $CERT_FOLDER"
Write-LogMessage "  Certificate file: $CRT_FILE"
Write-LogMessage "  Private key file: $KEY_FILE"
Write-LogMessage "  Certificate path: $CRT_FILE_PATH"
Write-LogMessage "  Private key path: $KEY_FILE_PATH"
Write-LogMessage ""
Write-LogMessage "All files in array: $FILES_ARRAY"
Write-LogMessage "=========================================="

# Check if files exist and analyze them
$CERT_COUNT = 0
$KEY_TYPE = "Unknown"
$KEY_FILE_CONTENT = ""
$CRT_FILE_CONTENT = ""

if (Test-Path $CRT_FILE_PATH) {
    $crtFileInfo = Get-Item $CRT_FILE_PATH
    Write-LogMessage "Certificate file exists: $CRT_FILE_PATH"
    Write-LogMessage "Certificate file size: $($crtFileInfo.Length) bytes"

    # Count certificates in the file
    $CRT_FILE_CONTENT = Get-Content $CRT_FILE_PATH -Raw
    $CERT_COUNT = ([regex]::Matches($CRT_FILE_CONTENT, "BEGIN CERTIFICATE")).Count
    Write-LogMessage "Total certificates in file: $CERT_COUNT"

    # Try to parse certificate using .NET
    try {
        # Extract just the first certificate if there are multiple
        if ($CRT_FILE_CONTENT -match '(?s)-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----') {
            $certBase64 = $matches[1] -replace '\s', ''
            $certBytes = [Convert]::FromBase64String($certBase64)
            $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @(,$certBytes)

            Write-LogMessage "Certificate details:"
            Write-LogMessage "  Subject: $($cert.Subject)"
            Write-LogMessage "  Issuer: $($cert.Issuer)"
            Write-LogMessage "  Serial Number: $($cert.SerialNumber)"
            Write-LogMessage "  Valid From: $($cert.NotBefore)"
            Write-LogMessage "  Valid To: $($cert.NotAfter)"
            Write-LogMessage "  Thumbprint: $($cert.Thumbprint)"
            Write-LogMessage "  Signature Algorithm: $($cert.SignatureAlgorithm.FriendlyName)"

            $cert.Dispose()
        }
    } catch {
        Write-LogMessage "Could not parse certificate details: $_"
    }
} else {
    Write-LogMessage "WARNING: Certificate file not found: $CRT_FILE_PATH"
}

if (Test-Path $KEY_FILE_PATH) {
    $keyFileInfo = Get-Item $KEY_FILE_PATH
    Write-LogMessage "Private key file exists: $KEY_FILE_PATH"
    Write-LogMessage "Private key file size: $($keyFileInfo.Length) bytes"

    # Read key file content and determine type
    $KEY_FILE_CONTENT = Get-Content $KEY_FILE_PATH -Raw

    if ($KEY_FILE_CONTENT -match "BEGIN RSA PRIVATE KEY") {
        $KEY_TYPE = "RSA"
        Write-LogMessage "Key type: RSA (BEGIN RSA PRIVATE KEY found)"
    } elseif ($KEY_FILE_CONTENT -match "BEGIN EC PRIVATE KEY") {
        $KEY_TYPE = "ECC"
        Write-LogMessage "Key type: ECC (BEGIN EC PRIVATE KEY found)"
    } elseif ($KEY_FILE_CONTENT -match "BEGIN PRIVATE KEY") {
        $KEY_TYPE = "PKCS#8 format (generic)"
        Write-LogMessage "Key type: PKCS#8 format (BEGIN PRIVATE KEY found)"
    } elseif ($KEY_FILE_CONTENT -match "BEGIN ENCRYPTED PRIVATE KEY") {
        $KEY_TYPE = "Encrypted PKCS#8"
        Write-LogMessage "Key type: Encrypted PKCS#8 format (BEGIN ENCRYPTED PRIVATE KEY found)"
    } else {
        $KEY_TYPE = "Unknown"
        Write-LogMessage "Key type: Unknown"
    }
} else {
    Write-LogMessage "WARNING: Private key file not found: $KEY_FILE_PATH"
}

# ============================================================================
# CUSTOM SCRIPT SECTION - CISCO FIREPOWER MANAGEMENT CENTER (FMC) DEPLOYMENT
# ============================================================================
#
# Available variables for the custom logic:
#
# Certificate-related variables:
#   $CERT_FOLDER      - The folder path where certificates are stored
#   $CRT_FILE         - The certificate filename (.crt)
#   $KEY_FILE         - The private key filename (.key)
#   $CRT_FILE_PATH    - Full path to the certificate file
#   $KEY_FILE_PATH    - Full path to the private key file
#   $FILES_ARRAY      - All files listed in the JSON files array
#
# Certificate inspection variables (if files exist):
#   $CERT_COUNT       - Number of certificates in the CRT file
#   $KEY_TYPE         - Type of key (RSA, ECC, PKCS#8 format, Encrypted PKCS#8, or Unknown)
#   $CRT_FILE_CONTENT - The full content of the certificate file
#   $KEY_FILE_CONTENT - The full content of the private key file
#
# Argument variables (from JSON args array):
#   $ARGUMENT_1       - FMC username:password
#   $ARGUMENT_2       - FMC hostname or IP (optionally prefixed with https://)
#   $ARGUMENT_3       - Internal Certificate object name in FMC
#
# JSON-related variables:
#   $JSON_STRING      - The complete decoded JSON string
#   $JSON_OBJECT      - The parsed JSON object
#   $ARGS_ARRAY       - The args array from JSON object
#
# Utility functions:
#   Write-LogMessage "text" - Function to write timestamped messages to log file
#   Mask-Password "text"    - Returns a masked placeholder for log output
#
# ============================================================================

Write-LogMessage "=========================================="
Write-LogMessage "Starting custom script section..."
Write-LogMessage "=========================================="

# ADD CUSTOM LOGIC HERE:
# ----------------------------------------

# --- Validate required arguments ---
if ([string]::IsNullOrEmpty($ARGUMENT_1) -or [string]::IsNullOrEmpty($ARGUMENT_2) -or [string]::IsNullOrEmpty($ARGUMENT_3)) {
    Write-LogMessage "ERROR: Expected 3 arguments (username:password, FMC host, certificate object name). Got: $($ARGS_ARRAY.Count)"
    Write-LogMessage "=========================================="
    exit 1
}

# --- Parse FMC credentials from ARGUMENT_1 (only the first ':' is the separator) ---
$FMC_USER = ""
$FMC_PASS = ""
$colonIndex = $ARGUMENT_1.IndexOf(':')
if ($colonIndex -gt 0) {
    $FMC_USER = $ARGUMENT_1.Substring(0, $colonIndex)
    $FMC_PASS = $ARGUMENT_1.Substring($colonIndex + 1)
    Write-LogMessage "Credentials parsed - Username: '$FMC_USER', Password: $(Mask-Password $FMC_PASS)"
} else {
    Write-LogMessage "ERROR: ARGUMENT_1 missing ':' separator. Expected username:password"
    Write-LogMessage "=========================================="
    exit 1
}

$FMC_HOST  = $ARGUMENT_2
$CERT_NAME = $ARGUMENT_3
Write-LogMessage "FMC_HOST: $FMC_HOST"
Write-LogMessage "CERT_NAME: $CERT_NAME"

# --- Require both certificate and key on disk ---
if (-not (Test-Path $CRT_FILE_PATH) -or -not (Test-Path $KEY_FILE_PATH)) {
    Write-LogMessage "ERROR: Certificate or private key file not found on disk - cannot continue"
    Write-LogMessage "=========================================="
    exit 1
}

$CERT_PEM = $CRT_FILE_CONTENT
$KEY_PEM  = $KEY_FILE_CONTENT
Write-LogMessage "Cert PEM ($($CERT_PEM.Length) chars) and key PEM ($($KEY_PEM.Length) chars) ready"

# --- Key passphrase ---
# If the TLM certificate profile sets a "Password for certificate files", the private key
# on disk is encrypted and the password is delivered in the payload. FMC's
# internalcertificates endpoint accepts an encrypted key plus passPhrase, so no local
# decryption is required.
$KEY_PASSPHRASE = $null
foreach ($field in @("password", "pfx_password", "keystore_password", "passphrase")) {
    $val = $JSON_OBJECT.$field
    if (-not [string]::IsNullOrEmpty($val)) {
        $KEY_PASSPHRASE = ($val -replace "[\r\n]", "")
        Write-LogMessage "Key passphrase located in payload field '$field' (length: $($KEY_PASSPHRASE.Length))"
        break
    }
}
if (-not $KEY_PASSPHRASE) {
    if ($KEY_TYPE -eq "Encrypted PKCS#8") {
        Write-LogMessage "WARNING: Key is encrypted but no passphrase found in payload - FMC import will likely fail"
    } else {
        Write-LogMessage "No key passphrase in payload (key is not encrypted)"
    }
}

# ============================================================================
# FMC REST API integration
# ============================================================================
Write-LogMessage "=========================================="
Write-LogMessage "Starting FMC REST API integration..."
Write-LogMessage "=========================================="

# --- TLS handling (FMC management interfaces commonly use self-signed certificates) ---
if ($PSVersionTable.PSVersion.Major -ge 6) {
    $skipCertCheck = @{ SkipCertificateCheck = $true }
} else {
    if (-not ("TrustAllCertsPolicy" -as [type])) {
        Add-Type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(ServicePoint sp, X509Certificate cert, WebRequest req, int problem) {
        return true;
    }
}
"@
        [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
    }
    $skipCertCheck = @{}
}
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

if ($FMC_HOST -match '^https?://') {
    $FmcBaseUrl = $FMC_HOST.TrimEnd('/')
} else {
    $FmcBaseUrl = "https://$FMC_HOST"
}
Write-LogMessage "FmcBaseUrl resolved to: $FmcBaseUrl"

# --- Step 1: Authenticate ---
Write-LogMessage "Step 1: Authenticating to FMC at $FmcBaseUrl..."
try {
    $authUri = "$FmcBaseUrl/api/fmc_platform/v1/auth/generatetoken"
    $authHeaderValue = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("$($FMC_USER):$($FMC_PASS)"))
    $authHeaders = @{ Authorization = "Basic $authHeaderValue" }

    $authResponse = Invoke-WebRequest -Uri $authUri -Method Post -Headers $authHeaders -UseBasicParsing @skipCertCheck -ErrorAction Stop

    $accessToken = "$($authResponse.Headers['X-auth-access-token'])"
    $domainUuid  = "$($authResponse.Headers['DOMAIN_UUID'])"

    if ([string]::IsNullOrEmpty($accessToken)) { throw "No access token returned - check credentials." }
    if ([string]::IsNullOrEmpty($domainUuid))  { throw "No DOMAIN_UUID returned in auth response." }
    Write-LogMessage "SUCCESS: Authenticated. Domain UUID: $domainUuid"
} catch {
    Write-LogMessage "ERROR: FMC authentication failed: $_"
    Write-LogMessage "=========================================="
    exit 1
}

$fmcHeaders = @{
    'X-auth-access-token' = $accessToken
    'Content-Type'        = 'application/json'
}
$certUri = "$FmcBaseUrl/api/fmc_config/v1/domain/$domainUuid/object/internalcertificates"

# --- Step 2: Look up an existing Internal Certificate object with the same name ---
Write-LogMessage "Step 2: Checking whether Internal Certificate '$CERT_NAME' already exists in FMC..."
$existingCertId = $null
try {
    $listUri = "$certUri" + "?expanded=true&limit=1000"
    $listResult = Invoke-RestMethod -Uri $listUri -Method Get -Headers $fmcHeaders @skipCertCheck -ErrorAction Stop
    if ($listResult.items) {
        $existing = $listResult.items | Where-Object { $_.name -eq $CERT_NAME } | Select-Object -First 1
        if ($existing) {
            $existingCertId = $existing.id
            Write-LogMessage "Existing object found. FMC object id: $existingCertId"
        }
    }
    if (-not $existingCertId) {
        Write-LogMessage "No existing object named '$CERT_NAME' - it will be created"
    }
} catch {
    Write-LogMessage "WARNING: Could not list existing Internal Certificate objects: $_"
    Write-LogMessage "Falling back to create"
}

# --- Step 3: Create or update the Internal Certificate object ---
$certBodyHash = @{
    name       = $CERT_NAME
    cert       = $CERT_PEM
    privateKey = $KEY_PEM
    type       = "InternalCertificate"
}
if ($KEY_PASSPHRASE) { $certBodyHash['passPhrase'] = $KEY_PASSPHRASE }

try {
    if ($existingCertId) {
        Write-LogMessage "Step 3: Updating Internal Certificate object '$CERT_NAME' (id $existingCertId) in FMC..."
        $certBodyHash['id'] = $existingCertId
        $certBody = $certBodyHash | ConvertTo-Json -Depth 10
        $certResult = Invoke-RestMethod -Uri "$certUri/$existingCertId" -Method Put -Headers $fmcHeaders -Body $certBody @skipCertCheck -ErrorAction Stop
        Write-LogMessage "SUCCESS: Certificate object updated. FMC object id: $($certResult.id)"
    } else {
        Write-LogMessage "Step 3: Creating Internal Certificate object '$CERT_NAME' in FMC..."
        $certBody = $certBodyHash | ConvertTo-Json -Depth 10
        $certResult = Invoke-RestMethod -Uri $certUri -Method Post -Headers $fmcHeaders -Body $certBody @skipCertCheck -ErrorAction Stop
        Write-LogMessage "SUCCESS: Certificate object created. FMC object id: $($certResult.id)"
    }
} catch {
    Write-LogMessage "ERROR: Failed to create/update certificate object in FMC: $_"
    if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
        Write-LogMessage "FMC response: $($_.ErrorDetails.Message)"
    }
    Write-LogMessage "=========================================="
    exit 1
}

Write-LogMessage "NOTE: The FMC object is updated. Policies referencing it must still be deployed to the managed devices."

# --- Step 4: Release the API session token ---
try {
    $revokeUri = "$FmcBaseUrl/api/fmc_platform/v1/auth/revokeaccess"
    Invoke-WebRequest -Uri $revokeUri -Method Post -Headers @{ 'X-auth-access-token' = $accessToken } -UseBasicParsing @skipCertCheck -ErrorAction Stop | Out-Null
    Write-LogMessage "Step 4: FMC access token revoked"
} catch {
    Write-LogMessage "Step 4: Could not revoke FMC access token (it will expire on its own): $_"
}

# ----------------------------------------
# END OF CUSTOM LOGIC

Write-LogMessage "Custom script section completed"
Write-LogMessage "=========================================="

# ============================================================================
# END OF CUSTOM SCRIPT SECTION
# ============================================================================

Write-LogMessage "=========================================="
Write-LogMessage "Script execution completed"
Write-LogMessage "=========================================="

exit 0
