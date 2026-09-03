# Remediation Plan

## Current Status

All original P0 findings have been remediated:

- Notify service access is protected by the internal service key.
- Webhook destinations are restricted to public HTTPS endpoints and private address ranges are rejected.
- The internal service key is no longer forwarded to external webhook destinations.
- JWT verification allows only the configured signing algorithm (`HS256`).
- Search uses an ORM query, is scoped to the requesting owner, and escapes LIKE wildcards.
- Individual scan reads enforce ownership.

The original P1 findings for password logging, hardcoded secrets, the share-link Host header, and outdated Python and Node.js dependencies have also been addressed. The share-link URL now uses the trusted `PUBLIC_BASE_URL` setting. The dependency manifests contain updated versions validated by the application test suites.

One high-severity dependency advisory remains because there is no upstream fix. The items below are intentionally deferred and require follow-up work before production deployment.

## Deferred Findings

### 1. Minerva timing attack in `ecdsa`

**Finding and current status**

OSV-Scanner reports `CVE-2024-23342` / `GHSA-wj6h-64fc-37mp` for `ecdsa==0.19.2`. This is the remaining HIGH dependency finding. The package is an indirect dependency of `python-jose`, and the advisory affects ECDSA signing and key-generation operations. The advisory states that the project does not plan to provide a fix.

**Why it is not fully remediated**

This application uses JWT with `HS256`; it does not use ECDSA signing, ECDH, P-256 key generation, or ECDSA private-key operations. Removing `ecdsa` without replacing the JWT library would break the current authentication dependency tree. The current version is the latest available version and fixes the other reported `ecdsa` vulnerabilities, but it cannot remove the timing-attack advisory.

**Residual risk**

The vulnerable code remains installed in the application environment. If future code starts using ECDSA signing or key generation, an attacker with a sufficiently capable timing measurement position could potentially infer private-key material. The risk is currently reduced by the fact that the application only uses HMAC-based JWTs, but dependency scanners will continue to report this advisory.

**Remediation effort**

Low to medium effort for the preferred approach: replace `python-jose` with a maintained JWT library that supports the application's required `HS256` behavior, update `app/auth.py`, and add compatibility and token-validation regression tests. A migration should also confirm token interoperability and deployment-wide key handling. Do not remove `ecdsa` manually while `python-jose` still requires it.

**Compensating controls**

- `app/auth.py` restricts JWT decoding to `HS256`.
- The application does not expose ECDSA signing, key-generation, or ECDH endpoints.
- `ecdsa` is pinned to `0.19.2`, the latest available version, and all other `ecdsa` advisories are remediated.
- The OSV exception is limited to `GHSA-wj6h-64fc-37mp` and must be reviewed if cryptographic functionality changes.

**Owner and trigger**

Application security owner. Reassess during the next authentication-library upgrade or before adding any asymmetric signing functionality.

### 2. Unrestricted credentialed CORS and verbose exception responses

**Finding and current status**

The FastAPI middleware reflects any supplied `Origin` and sets `Access-Control-Allow-Credentials: true`. The global exception handler returns the exception message, exception type, traceback, and request URL. This finding remains open as a MEDIUM-risk hardening issue.

**Why it is not fully remediated**

The current prototype has no documented browser frontend or production origin allowlist, so selecting an allowlist requires a deployment decision. The exception response is useful during development, but changing it safely requires separating production and development error handling and ensuring logs retain enough diagnostic context.

**Residual risk**

A browser-based client may be able to make credentialed cross-origin requests from an untrusted origin if the browser accepts the reflected CORS policy. Error responses can disclose filesystem paths, internal URLs, exception details, and implementation information. Exploitation depends on browser use and the application's authentication delivery model, but the configuration is unsafe for production.

**Remediation effort**

Low effort: replace origin reflection with an explicit production allowlist, reject or omit credentials for untrusted origins, and add correct preflight handling. Low effort: return a generic error identifier and message to clients while logging the full exception server-side. Add tests for allowed and denied origins and for production error-response redaction.

**Compensating controls**

- The API uses bearer tokens rather than browser cookies for authentication.
- All normal protected routes require authentication and ownership checks.
- The service should be deployed behind TLS and an authenticated ingress.
- Until fixed, do not expose the API to arbitrary browser origins and avoid using it with browser-managed credentials.

**Owner and trigger**

API/platform owner. Must be remediated before browser clients or production public exposure are introduced.

### 3. Unbounded or arbitrary webhook metadata

**Finding and current status**

The notify service copies caller-supplied `metadata` into the in-memory webhook record. No privileged fields are currently read from this object. This remains a LOW-risk design weakness rather than an active privilege-escalation vulnerability.

**Why it is not fully remediated**

Metadata is currently informational and the service is an in-memory prototype. Introducing a schema now would add an API decision without addressing an exploitable authorization path in the current implementation.

**Residual risk**

Large or unexpected metadata can consume memory, pollute logs or responses, and create a future confused-deputy issue if later code treats metadata as trusted policy or authorization data. The risk increases if registrations become persistent or metadata is rendered by an administrative UI.

**Remediation effort**

Low effort: define an allowlisted metadata schema, cap serialized size and key count, reject prototype keys such as `__proto__`, `constructor`, and `prototype`, and add validation tests. Medium effort if metadata becomes persistent or user-visible because output encoding and migration controls will also be needed.

**Compensating controls**

- Webhook management and notification endpoints require `X-Service-Key`.
- Metadata is copied into a fresh object and is not used for routing, authorization, or dispatch policy.
- The service currently stores registrations only in memory.

**Owner and trigger**

Notify service owner. Reassess before persistent storage, administrative UI exposure, or use of metadata in policy decisions.

### 4. CSRF middleware is absent from the notify service

**Finding and current status**

Semgrep did not identify CSRF middleware in the Express service. This is currently INFORMATIONAL, not an active high-severity vulnerability.

**Why it is not fully remediated**

The notify API is designed for service-to-service and API-client access using `X-Service-Key`; it does not use browser cookie sessions. CSRF protection is therefore not the primary control for the current authentication model. Adding browser-oriented CSRF middleware without first defining a browser session flow would not address the main threat.

**Residual risk**

If the service later accepts browser requests authenticated by cookies, a malicious website could cause state-changing requests from a victim browser unless CSRF protection and appropriate cookie attributes are added. With the current header-based service authentication, browsers do not automatically attach the required service key.

**Remediation effort**

Low to medium effort if browser access is introduced: use a session design with `SameSite` and `Secure` cookies, add synchronizer-token or double-submit-token protection, validate `Origin`/`Referer` where appropriate, and test every state-changing route. No additional CSRF implementation is required for the current header-authenticated API-only design.

**Compensating controls**

- State-changing notify routes require the custom `X-Service-Key` header.
- Browsers do not automatically send that custom header cross-site.
- The API should remain inaccessible from arbitrary public browser clients.

**Owner and trigger**

Notify service owner. Reassess immediately if cookie authentication, browser administration, or a public web frontend is added.

## Review Schedule

Review this plan at every dependency update, authentication change, and deployment architecture change. The `ecdsa` exception requires explicit review whenever cryptographic operations or JWT algorithms change.
