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
| P1 (remediated) | The public share-link URL trusted the incoming `Host` header. | Manual review of `app/main.py` | **High.** Before remediation, an authenticated user could create a link pointing to an attacker-controlled host. | The generated link could be used for phishing or to capture a stakeholder's password. | New feature; fixed with trusted `PUBLIC_BASE_URL` |
| P1 (remediated; residual exception) | `python-jose` and its transitive dependencies were outdated. | OSV-Scanner, SCA | **High.** The original scan reported advisories in the JWT dependency tree. | Crafted authentication input could have bypassed token integrity or caused denial of service. | Starter code; updated to `python-jose==3.5.0`, with the `ecdsa` Minerva advisory documented in `docs/remediation-plan.md` |
| P1 (remediated) | The FastAPI runtime dependency set was materially outdated. | OSV-Scanner, SCA | **High.** The original scan reported vulnerable framework, parser, and cryptography versions. | Malformed HTTP or multipart traffic could reduce availability. | Starter code; updated Python dependencies |
| P1 (remediated) | `axios` and the Express routing dependency chain contained outdated packages. | OSV-Scanner, SCA | **High.** The original scan reported Axios and routing dependency advisories. | Outdated dependencies amplified the webhook SSRF path and could permit request manipulation or denial of service. | Starter code; updated direct and transitive Node.js dependencies |
| P1 (residual) | `ecdsa` is affected by the Minerva timing attack on P-256. | OSV-Scanner, SCA | **High.** The advisory has no upstream fix and affects the full available `ecdsa` version range. | Future use of ECDSA signing or key generation could expose private-key material through timing analysis. | Transitive dependency; current HS256-only use and compensating controls are documented in `docs/remediation-plan.md` |
| P2 | API responses reflect arbitrary origins with credentialed CORS enabled, and unhandled exceptions disclose stack traces and request details. | Manual review of `app/main.py` | **Medium.** Either flaw broadens exposure, but practical exploitation depends on browser use, an existing credential mechanism, or an application error. | Cross-origin requests may be trusted too broadly, while error responses reveal internal paths and implementation details that help attackers develop follow-on attacks. | Starter code |
| P3 | Arbitrary webhook metadata is copied into the stored registration object. | Semgrep Community Edition, SAST; manual review of `notify/src/index.js` | **Low.** The current object has no privileged fields that can be overwritten, and the metadata is not used for authorization or dispatch policy. | Unbounded or unexpected metadata can complicate operations and becomes more dangerous if future code treats it as trusted configuration. | Starter code |
| P3 | Semgrep did not find CSRF middleware in the Express service. | Semgrep Community Edition, SAST | **Informational.** This is not currently a browser-cookie session application; the material issue is missing authentication, not missing CSRF tokens. | Adding CSRF middleware alone would not prevent API clients from creating or abusing webhook registrations. Reassess if browser sessions or cookie authentication are introduced. | Starter code |

## Prioritization Notes

The first remediation milestone removed the JWT `none` acceptance, enforced
ownership for single-record reads and search, parameterized search queries, and
removed password logging. The notification service now has authenticated
service-to-service access, strict URL validation, and no service-key forwarding
to external destinations. Dependency upgrades were completed with regression
testing; the remaining `ecdsa` advisory has no upstream fix and is tracked in
`docs/remediation-plan.md`.

The share-link implementation deliberately uses high-entropy opaque tokens,
24-hour expiry, bcrypt password hashing, a public response that excludes the
scan owner identifier, and a public URL derived from trusted deployment
configuration rather than the incoming `Host` header.