# DigiCert TLM Agent — Cisco Firepower Management Center (FMC) AWR Post-Enrollment Script

Automated certificate deployment to Cisco Firepower Management Center using a DigiCert Trust Lifecycle Manager (TLM) Agent post-enrollment Admin Web Request (AWR) script. After TLM enrolls or renews a certificate, the script pushes the new certificate and private key into FMC as an **Internal Certificate** object via the FMC REST API.

## Overview

The script is triggered automatically by the TLM Agent once a certificate has been issued and written to disk. It:

1. Decodes the AWR payload the agent passes in `DC1_POST_SCRIPT_DATA`
2. Locates the `.crt` and `.key` files and inspects them (certificate count, subject, expiry, key type)
3. Authenticates to FMC and obtains an API token
4. Creates the Internal Certificate object if it does not exist, or updates it in place if an object with the same name already exists
5. Revokes the API token and exits

The script follows the standard DigiCert AWR post-enrollment flow: legal notice gate, payload decoding, argument extraction, and certificate inspection. The FMC deployment logic lives in the **CUSTOM SCRIPT SECTION** near the bottom of the file.

## Scripts

| File | Platform | Shell |
|------|----------|-------|
| `admin-webrequest-post-script/Windows/cisco-firepower-awr.ps1` | Windows | PowerShell 5.1 / 7+ |

## Prerequisites

### DigiCert TLM Agent

- **TLM Agent** installed on a Windows host with an active certificate profile
- The certificate profile must produce a **separate `.crt` and `.key` file** (PEM). The script selects the first `.crt` and the first `.key` in the AWR `files` array; a PFX-only profile will not work
- If the profile sets a **Password for certificate files**, the private key on disk is encrypted. The script reads that password from the payload and passes it to FMC as the `passPhrase`, so encrypted keys are supported without local decryption
- The post-enrollment (AWR) script must be registered in the agent configuration with the **three arguments** described in [AWR Arguments](#awr-arguments)
- The TLM Agent must be able to run PowerShell scripts (execution policy must allow it)

### Cisco Firepower Management Center

- FMC **REST API enabled** (System → Configuration → REST API Preferences; enabled by default on current releases)
- FMC reachable from the TLM Agent host on HTTPS (port 443)
- An FMC account able to write objects. See [FMC Account Permissions](#fmc-account-permissions)
- FMC 6.x or later. The script uses `/api/fmc_platform/v1/auth/generatetoken` and `/api/fmc_config/v1/.../object/internalcertificates`

### PowerShell

- **PowerShell 7 (Core) is recommended**. It uses `Invoke-RestMethod -SkipCertificateCheck` for the FMC management certificate
- PowerShell 5.1 works via a fallback `TrustAllCertsPolicy` type that disables certificate validation **process-wide**. Prefer PowerShell 7 where possible
- TLS 1.2 is forced for all FMC calls

## FMC Account Permissions

The script touches three classes of endpoint:

| Script step | Endpoint | Requirement |
|-------------|----------|-------------|
| 1 Authenticate | `POST /api/fmc_platform/v1/auth/generatetoken` | Any FMC user with API access |
| 2 Look up existing object | `GET /api/fmc_config/v1/domain/{uuid}/object/internalcertificates` | Read access to Object Manager |
| 3 Create / update object | `POST` or `PUT .../object/internalcertificates[/{id}]` | Write access to Object Manager |
| 4 Revoke token | `POST /api/fmc_platform/v1/auth/revokeaccess` | Same user as step 1 |

Use a **dedicated local FMC account** with the **Administrator** or **Network Admin** role, or a custom role that grants *Objects → Object Management* with modify rights. Users authenticated through an external server (LDAP / RADIUS) can also use the API if their mapped role permits object writes, but a local account keeps the permission explicit.

FMC limits each user to a small number of concurrent API sessions and each token to 30 minutes. The script revokes its token on completion so repeated renewals do not exhaust the session limit.

## Configuration

### Script Variables

Edit the variables at the top of the script before deployment:

```powershell
# Legal notice must be accepted to run — ships as "false", you MUST change it
$LEGAL_NOTICE_ACCEPT = "false"

# Log file location (directory is created automatically if missing)
$LOGFILE = "C:\Program Files\DigiCert\TLM Agent\log\fmc_awr.log"
```

`LEGAL_NOTICE_ACCEPT` ships as `"false"` and must be set to `"true"` or the script exits immediately with code 1 after writing the reason to the log.

### AWR Arguments

The script receives three arguments via the TLM Agent AWR configuration, passed through the `DC1_POST_SCRIPT_DATA` environment variable as a Base64-encoded JSON payload:

| Argument | Description | Example | Required |
|----------|-------------|---------|----------|
| `Argument 1` | FMC credentials (`user:pass`) | `admin:P@ssw0rd` | Yes |
| `Argument 2` | FMC hostname or IP, with or without `https://` | `fmc.example.com` or `https://10.0.0.5` | Yes |
| `Argument 3` | Internal Certificate object name in FMC | `www-example-com` | Yes |

Only the first `:` in Argument 1 is treated as the user/password separator, so colons inside the password are safe. The payload is parsed with `ConvertFrom-Json`, so commas and quotes in the password are also safe. Whitespace is stripped from every argument, so the password **must not contain spaces**.

Any arguments beyond the third are ignored. The script logs a note with the count of unused arguments so a misconfigured AWR is visible in the log.

## How It Works

Step numbers below match the `Step N:` entries written to the log file.

```
TLM Agent enrolls/renews cert
        │
        ▼
┌─────────────────────────┐
│ Legal notice gate       │  ← exit 1 unless $LEGAL_NOTICE_ACCEPT = "true"
└────────┬────────────────┘
         ▼
┌─────────────────────────┐
│ Decode AWR payload      │  ← DC1_POST_SCRIPT_DATA (Base64 → JSON)
│    Extract 3 args       │     Raw JSON logged with credentials masked
│    Locate .crt / .key   │
│    Inspect cert + key   │     cert count, subject, expiry, key type
└────────┬────────────────┘
         ▼
┌─────────────────────────┐
│ 1. Authenticate to FMC  │  ← POST /api/fmc_platform/v1/auth/generatetoken
│                         │     returns X-auth-access-token + DOMAIN_UUID
└────────┬────────────────┘
         ▼
┌─────────────────────────┐
│ 2. Look up existing     │  ← GET .../object/internalcertificates?expanded=true
│    object by name       │
└────────┬────────────────┘
         ▼
┌─────────────────────────┐
│ 3. Create or update     │  ← POST .../internalcertificates          (new)
│    Internal Certificate │     PUT  .../internalcertificates/{id}    (existing)
│                         │     body: name, cert, privateKey, passPhrase
└────────┬────────────────┘
         ▼
┌─────────────────────────┐
│ 4. Revoke API token     │  ← POST /api/fmc_platform/v1/auth/revokeaccess
└─────────────────────────┘
```

### Exit codes

Unlike some sibling AWR scripts, this script **stops on the first FMC failure**:

| Exit code | Meaning |
|-----------|---------|
| `0` | Object created or updated in FMC |
| `1` | Preflight failure (legal notice, missing payload, bad JSON, missing arguments, cert/key not on disk) or FMC failure (authentication or create/update) |

A failed lookup in step 2 is logged as a `WARNING` and the script falls back to a create.

### Create vs. update

On first run no object exists, so the script POSTs a new Internal Certificate. On every renewal the object is found by name and updated with PUT, keeping the same FMC object id. Any policy or device configuration that references the object therefore keeps working without re-selection.

## FMC API Endpoints Used

| Method | Endpoint | Purpose |
|--------|----------|---------|
| `POST` | `/api/fmc_platform/v1/auth/generatetoken` | Authenticate, obtain token and domain UUID |
| `GET` | `/api/fmc_config/v1/domain/{uuid}/object/internalcertificates?expanded=true&limit=1000` | Find existing object by name |
| `POST` | `/api/fmc_config/v1/domain/{uuid}/object/internalcertificates` | Create Internal Certificate |
| `PUT` | `/api/fmc_config/v1/domain/{uuid}/object/internalcertificates/{id}` | Update Internal Certificate |
| `POST` | `/api/fmc_platform/v1/auth/revokeaccess` | Release the API session |

## Assumptions and Limitations

- **No policy deployment.** Updating the object changes FMC's configuration only. Managed devices (FTD) do not receive the new certificate until a **policy deployment** is run from FMC. Deploy after each renewal, or automate deployment separately.
- **Global domain only.** The script uses the `DOMAIN_UUID` returned at login, which is the domain the account is scoped to. Multi-domain FMC deployments where the object must live in a child domain are not handled.
- **Object lookup is capped at 1000 objects.** If the FMC holds more than 1000 Internal Certificate objects, an existing object beyond that page will not be found and the create will fail with a duplicate-name error.
- **Separate `.crt` and `.key` files are required.** Combined PEM bundles and PFX output are not supported.
- **The full `.crt` content is sent as `cert`.** If the TLM profile emits the end-entity certificate plus chain in one file, the whole bundle is uploaded. FMC uses the first certificate as the identity certificate.
- **Management TLS verification is disabled** (`SkipCertificateCheck` / `TrustAllCertsPolicy`) to allow self-signed FMC management certificates.
- **No rollback.** If the PUT fails after authentication, the previous object is left unchanged and the script exits 1.

## Logging

The script produces a detailed, timestamped log. Credentials and passwords are masked everywhere they appear. The log includes:

- Configuration summary
- The raw decoded JSON payload with the password half of `args[0]` and any `password` / `passphrase` fields replaced by `********`
- The three arguments (Argument 1 logged as `user:********`)
- Certificate and key file metadata (size, certificate count, subject, issuer, serial, validity, thumbprint, key type)
- Each FMC step result with the FMC object id on success and the FMC error body on failure

Default log location:

- **Windows:** `C:\Program Files\DigiCert\TLM Agent\log\fmc_awr.log`

The log directory is created automatically if it does not exist. The log is never rotated or truncated; it appends indefinitely.

## Security Considerations

- **Credentials** are passed via the AWR argument payload and are never written to the log in cleartext
- The **private key** is read into memory and sent to FMC over HTTPS. It is never written anywhere other than the location TLM already placed it
- The key passphrase from the payload is sent to FMC as `passPhrase` and is masked in the log
- TLS certificate verification for the FMC management interface is disabled to support self-signed certificates. Use a trusted certificate on the FMC management interface in production where possible
- Use a **dedicated FMC service account** limited to object management rather than a shared `admin` login
- The `LEGAL_NOTICE_ACCEPT` flag must be explicitly set to `"true"` before the script will execute

## Supported Key Types

The script detects and logs the private key type:

- RSA (`BEGIN RSA PRIVATE KEY`)
- ECC (`BEGIN EC PRIVATE KEY`)
- PKCS#8 (`BEGIN PRIVATE KEY`)
- Encrypted PKCS#8 (`BEGIN ENCRYPTED PRIVATE KEY`)

Detection is for logging and for the passphrase warning only. An unrecognised header is logged as `Unknown` and the upload still proceeds.

## Troubleshooting

| Symptom | Likely Cause | Fix |
|---------|-------------|-----|
| Script exits immediately, log says legal notice not accepted | `$LEGAL_NOTICE_ACCEPT` still `"false"` | Edit the variable at the top of the script |
| `DC1_POST_SCRIPT_DATA environment variable is not set` | Script not invoked by the TLM Agent AWR | Verify the post-enrollment script path in the agent configuration |
| `Expected 3 arguments` | AWR arguments not configured | Configure Arguments 1 to 3 as described in [AWR Arguments](#awr-arguments) |
| `ARGUMENT_1 missing ':' separator` | Credentials not in `user:pass` form | Fix Argument 1 |
| `Certificate or private key file not found on disk` | Profile does not emit separate `.crt` / `.key` files | Change the TLM certificate profile output format |
| `FMC authentication failed` with 401 | Wrong credentials or account lacks API access | Check Argument 1 and the account role |
| `FMC authentication failed` with a session-limit message | Too many open API sessions for that user | Wait for tokens to expire, or use a dedicated account |
| `Connection refused` / timeout | FMC unreachable from the agent host | Check Argument 2, firewall rules, and that the REST API is enabled |
| Create fails with a duplicate-name error | Object exists but was not found by the lookup | Check the FMC error body in the log; see the 1000-object limitation |
| Create/update fails mentioning the private key or passphrase | Key is encrypted and no passphrase was in the payload, or the key does not match the certificate | Confirm the TLM profile password setting and check the `Key type` line in the log |
| Object updated but devices still present the old certificate | Policy not deployed | Run a policy deployment from FMC |
| `Could not parse certificate details` | `.crt` is not PEM or is malformed | Inspect the file; the upload is still attempted |

## License

Copyright © 2026 DigiCert, Inc. All rights reserved. See the legal notice in the script for full terms.
