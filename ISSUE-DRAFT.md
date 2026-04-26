# Silent false positives when service principal lacks required Graph API permissions (M365)

## Description

When the M365 service principal is missing required Graph API permissions (e.g. `AuditLog.Read.All`), multiple service methods silently swallow 403 errors and return empty defaults. Downstream checks then interpret empty data as "no users/resources exist" or "all users fail the check", producing mass false positives with no indication that permission errors occurred.

This is not limited to one check — it is a systemic pattern across the M365 provider, and partially present in Azure.

## Steps to reproduce

1. Register an M365 service principal with all required permissions **except** `AuditLog.Read.All`
2. Run a scan against the M365 provider
3. Observe `entra_users_mfa_capable` reports **every enabled user** as FAIL ("User X is not MFA capable")
4. The scan completes with state `completed` and 100% progress — no warnings, no errors visible in the UI
5. The only clue is a `logger.error()` line in worker logs that is not surfaced anywhere

**Expected**: A clear signal that the check could not run due to insufficient permissions.
**Actual**: 240 false-positive FAILs indistinguishable from genuine findings.

## Root cause analysis

The problem exists at three layers:

### Layer 1 — Service: silent error swallowing

Service data-fetching methods catch 403/ODataError and return empty defaults (empty dict, empty list, or `None`) without propagating the error to the caller. The caller cannot distinguish "API returned no data" from "API call failed due to missing permissions".

**M365 methods with this anti-pattern:**

| Service | Method | Returns on 403 | Required permission |
|---------|--------|----------------|-------------------|
| Entra | `_get_user_registration_details` | `{}` | AuditLog.Read.All |
| Entra | `_get_oauth_apps` | `None` | ThreatHunting.Read.All |
| Entra | `_get_authentication_method_configurations` | `{}` | Policy.Read.All |
| SharePoint | `_get_settings` | `None` | SharePoint permissions |
| DefenderIdentity | `_get_sensors` | `None` | SecurityIdentitiesSensors.Read.All |
| DefenderIdentity | `_get_health_issues` | `None` | SecurityIdentitiesHealth.Read.All |

**Only 2 of ~12 Entra methods properly propagate errors** (`_get_directory_sync_settings` returns a `(data, error_message)` tuple — this is the correct pattern but it's not enforced).

### Layer 2 — Checks: no awareness of degraded data

Checks consume service attributes at face value. When `is_mfa_capable` defaults to `False` for every user (because registration details couldn't be fetched), the check dutifully reports every user as FAIL. There is no mechanism for a check to know its input data is degraded.

Some checks do handle this (e.g. `entra_seamless_sso_disabled` checks `entra_client.directory_sync_error`), but this is ad-hoc — each check author must know to look for an error attribute that may or may not exist.

### Layer 3 — Scan: no "completed with warnings" state

The scan state machine has: `available` → `executing` → `completed` (or `failed`). A scan that couldn't run 20% of its checks due to missing permissions shows the same `completed` / 100% as a fully successful scan. The UI and API provide no signal that something was degraded.

## Suggested implementation

### Phase 1 — Standardize error propagation in M365 services (minimal, backward-compatible)

Apply the `(data, error_message)` tuple return pattern (already used by `_get_directory_sync_settings`) to all M365 service methods that call external APIs:

```python
# Before (current pattern in most methods)
async def _get_oauth_apps(self):
    oauth_apps = {}
    try:
        # ... fetch data ...
    except Exception as error:
        logger.error(f"{error.__class__.__name__}[...]: {error}")
    return oauth_apps  # empty dict on failure — caller can't tell

# After (standardized pattern)
async def _get_oauth_apps(self):
    oauth_apps = {}
    error_message = None
    try:
        # ... fetch data ...
    except ODataError as error:
        error_code = getattr(error.error, "code", None) if error.error else None
        if error_code in ("Authorization_RequestDenied", "Authentication_MSGraphPermissionMissing") or \
           error.__dict__.get("response_status_code", None) == 403:
            error_message = "Insufficient privileges. Required permission: ThreatHunting.Read.All"
            logger.error(f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error_message}")
        else:
            logger.error(f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}")
            error_message = str(error)
    except Exception as error:
        logger.error(f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}")
        error_message = str(error)
    return oauth_apps, error_message
```

Store each error as `self.<attribute>_error` on the service class (matching existing `self.directory_sync_error` convention). Update affected checks to emit a single descriptive FAIL when the error attribute is set, instead of iterating over empty data.

### Phase 2 — Upfront permission validation at provider init

Add a permission check during M365 provider initialization that queries the service principal's granted app roles and compares them against the required set:

```python
# In M365Provider.__init__ or Entra.__init__
async def _validate_permissions(self):
    """Check granted Graph API permissions against required set and warn about gaps."""
    required = {
        "AuditLog.Read.All": "User MFA registration details",
        "SecurityEvents.Read.All": "Security events",
        "Policy.Read.All": "Authentication method configurations",
        # ... full map ...
    }
    
    # GET /servicePrincipals/{id}/appRoleAssignments
    granted = await self._get_granted_permissions()
    
    missing = {perm: desc for perm, desc in required.items() if perm not in granted}
    if missing:
        for perm, desc in missing.items():
            logger.warning(f"Missing permission {perm} — {desc} checks will be degraded")
        self.permission_warnings = missing
    else:
        self.permission_warnings = {}
```

This doesn't block scanning — it logs warnings and stores the gaps so checks can reference them. The information is available before any check runs.

### Phase 3 — Scan state: "completed_with_warnings"

Add a new scan terminal state (or a warnings counter on the existing `completed` state) that surfaces when checks encountered permission errors:

**Option A — New state:**
```
available → executing → completed | completed_with_warnings | failed
```

**Option B — Warnings field on scan (less breaking):**
```python
class Scan:
    state: str  # completed
    warnings: list[str] = []  # ["Missing AuditLog.Read.All: MFA checks degraded"]
```

Option B is less disruptive to the API contract and UI. The scan still shows as `completed` but carries a warnings list that the UI can surface as a banner or badge.

The scan runner would collect warnings from service-level errors:
```python
# In perform_prowler_scan(), after checks complete:
warnings = []
if hasattr(provider_service, 'user_registration_error') and provider_service.user_registration_error:
    warnings.append(provider_service.user_registration_error)
if hasattr(provider_service, 'permission_warnings'):
    for perm, desc in provider_service.permission_warnings.items():
        warnings.append(f"Missing {perm}: {desc}")

scan_instance.warnings = warnings
scan_instance.save()
```

## Scope

| Phase | Effort | Impact |
|-------|--------|--------|
| 1 — Error propagation | ~5 methods + ~5 checks | Eliminates false positives from permission gaps |
| 2 — Permission validation | 1 new method per provider | Early warning before scan starts |
| 3 — Scan warnings | API model change + UI | Operator visibility in dashboard |

Phase 1 is the minimum viable fix. Phases 2 and 3 are improvements that prevent the problem class entirely.

## Affected checks (Phase 1 scope)

- `entra_users_mfa_capable` — false FAIL for all users (fixed in this PR)
- `entra_break_glass_account_fido2_security_key_registered` — false FAIL (fixed in this PR)
- `entra_app_registration_no_unused_privileged_permissions` — false PASS (oauth_apps returns None)
- Checks consuming `authentication_method_configurations` — untested
- `defenderidentity_health_issues_no_open` — already handles None but inconsistently
- SharePoint checks consuming `_get_settings` — untested
