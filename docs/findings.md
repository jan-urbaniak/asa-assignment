# Security Findings

## Scope and Method

This assessment covers the FastAPI service in `app/` and the Express notification
service in `notify/`. Semgrep Community Edition performed static analysis of both
source directories. OSV-Scanner assessed pinned Python and Node.js dependencies
from `requirements.txt` and `notify/package-lock.json`. Manual review was used to
validate reachability, identify authorization flaws, and assess business impact.

| Priority | Finding | Source and scan type | Severity and rationale | Business impact | Origin |
| --- | --- | --- | --- | --- | --- |
| P0 | Unauthenticated users can register webhooks, trigger dispatch, and enumerate or delete registrations. | Manual review of `notify/src/index.js` | **Critical.** The service exposes state-changing and sensitive operational endpoints without an identity or service-to-service authentication boundary. | An internet-reachable notification service can be manipulated to intercept scan events, disrupt alert delivery, or remove legitimate stakeholder integrations. | Starter code |
| P0 | User-controlled webhook URLs enable server-side request forgery (SSRF). The dispatcher sends an internal service key to every target. | Manual review of `notify/src/index.js` and `notify/src/dispatcher.js` | **Critical.** An attacker can register an internal, loopback, link-local, or cloud metadata URL and cause the service to send a request with `X-Service-Key`. | This can expose service credentials, reach internal management endpoints, access cloud metadata, or use the notification service as a pivot inside the network. | Starter code |
| P0 | The JWT verifier accepts the `none` algorithm. | Semgrep Community Edition, SAST; manual validation in `app/auth.py` | **Critical.** A forged unsigned token can be accepted where the token header selects `none`, bypassing the integrity guarantee on bearer tokens. | An attacker could impersonate a user and access or alter vulnerability records, affecting confidentiality and remediation integrity. | Starter code |
| P0 | Search constructs SQL with untrusted text interpolation and does not constrain results to the requesting owner. | Semgrep Community Edition, SAST; manual validation in `app/database.py` and `app/main.py` | **Critical.** The `q` parameter reaches a raw f-string SQL statement. The search endpoint also returns matching scans across user boundaries. | An authenticated user can retrieve another tenant's vulnerability data and may be able to alter query behavior through SQL injection. | Starter code |
| P0 | Reading an individual scan does not enforce scan ownership. | Manual review of `app/main.py` | **High.** `GET /scans/{scan_id}` authenticates the caller but queries only by identifier. Sequential IDs make unauthorized discovery straightforward. | Any logged-in user can access other users' vulnerability titles, affected components, descriptions, and remediation notes. | Starter code |
| P1 | Plaintext passwords are written to application logs during successful and failed sign-in attempts. | Semgrep Community Edition, SAST; manual validation in `app/main.py` | **High.** Passwords are sensitive credentials; log access is commonly broader and retention is commonly longer than production database access. | A log reader, backup operator, or incident responder can reuse customer credentials against this and potentially other systems. | Starter code |
| P1 | Application and service secrets are hardcoded in source control. | Manual review of `app/config.py` and `notify/src/config.js` | **High.** The JWT signing key, database password, API key, and notification service key are committed as plaintext values. | Anyone with repository access can forge tokens or authenticate to dependent services. Rotation is required because historical clones and CI logs may retain the values. | Starter code |
| P1 | The public share-link URL trusts the incoming `Host` header. | Manual review of `app/main.py` | **High.** An authenticated user can create a valid share token while supplying an attacker-controlled host, producing a convincing link to an untrusted domain. | Stakeholders may be directed to phishing infrastructure or disclose the report password to an attacker. The token itself remains random, but the generated URL becomes an unsafe security communication artifact. | New feature |
| P1 | `python-jose` 3.3.0 has high and critical published advisories. | OSV-Scanner, SCA | **High.** The scanner reports advisories up to CVSS 9.3 for `python-jose` and transitive cryptographic packages. This library processes attacker-supplied bearer tokens. | A vulnerable authentication dependency increases the chance that crafted tokens bypass controls or cause denial of service. The existing JWT configuration flaw makes prompt remediation more urgent. | Starter code |
| P1 | The FastAPI runtime dependency set is materially outdated: `fastapi` 0.104.1, `starlette` 0.27.0, `python-multipart` 0.0.6, and `cryptography` 38.0.1 have high-severity advisories. | OSV-Scanner, SCA | **High.** The report includes CVSS scores up to 8.7 across the HTTP framework, request parsers, and cryptography runtime. Several issues concern host handling and denial of service. | Malformed HTTP or multipart traffic could reduce availability, and framework issues can weaken request-boundary assumptions. Some multipart findings have limited reachability because this API currently has no upload route. | Starter code |
| P1 | `axios` 0.21.1 and the Express routing dependency chain contain high-severity advisories. | OSV-Scanner, SCA | **High.** OSV reports Axios advisories up to CVSS 8.6 and `path-to-regexp` ReDoS advisories up to 7.7. Axios is directly used for attacker-influenced outbound requests. | Outdated dependencies amplify the webhook SSRF path and can permit request manipulation or denial of service. Updating them is necessary, though it does not replace URL allowlisting and egress controls. | Starter code |
| P2 | API responses reflect arbitrary origins with credentialed CORS enabled, and unhandled exceptions disclose stack traces and request details. | Manual review of `app/main.py` | **Medium.** Either flaw broadens exposure, but practical exploitation depends on browser use, an existing credential mechanism, or an application error. | Cross-origin requests may be trusted too broadly, while error responses reveal internal paths and implementation details that help attackers develop follow-on attacks. | Starter code |
| P3 | Arbitrary webhook metadata is copied into the stored registration object. | Semgrep Community Edition, SAST; manual review of `notify/src/index.js` | **Low.** The current object has no privileged fields that can be overwritten, and the metadata is not used for authorization or dispatch policy. | Unbounded or unexpected metadata can complicate operations and becomes more dangerous if future code treats it as trusted configuration. | Starter code |
| P3 | Semgrep did not find CSRF middleware in the Express service. | Semgrep Community Edition, SAST | **Informational.** This is not currently a browser-cookie session application; the material issue is missing authentication, not missing CSRF tokens. | Adding CSRF middleware alone would not prevent API clients from creating or abusing webhook registrations. Reassess if browser sessions or cookie authentication are introduced. | Starter code |

## Prioritization Notes

The first remediation milestone should remove the JWT `none` acceptance, enforce
ownership for single-record reads and search, parameterize search queries, and
remove password logging. The notification service then needs authenticated
service-to-service access, authorization for webhook management, strict URL
validation, and network egress restrictions. Dependency upgrades should follow
with regression testing because the pinned versions are several release lines
behind supported versions.

The share-link implementation deliberately uses high-entropy opaque tokens,
24-hour expiry, bcrypt password hashing, and a public response that excludes
the scan owner identifier. Its remaining Host-header issue should be remediated
by deriving the public base URL from a trusted deployment setting, or by
configuring a trusted proxy boundary that sanitizes forwarded host and scheme
headers before they reach the application.