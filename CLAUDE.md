# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Keycloak SPI plugin that adds OTP authentication via **email** and **SMS** channels. Multi-module Maven project producing a single deployable JAR.

- **Keycloak version**: 26.8.1
- **Java**: 21
- **Build system**: Maven (multi-module)

## Project Structure

```
common/     — Shared constants, SMS SPI interfaces and default log provider (keycloak-otp-common)
otp-2fa/    — Browser flow authenticators for 2FA (keycloak-otp-2fa)
otp-login/  — Custom OAuth2 grant types for OTP login (keycloak-otp-login)
themes/     — Pure resource JAR with FreeMarker templates + messages (keycloak-otp-themes)
dist/       — Single deployable JAR via maven-shade-plugin (keycloak-otp)
```

## Build & Test Commands

```bash
mvn clean package                                              # Build all JARs
mvn test                                                       # Run all tests
mvn test -pl common                                            # Run only common tests
mvn test -pl otp-2fa                                           # Run only 2FA tests
mvn test -pl otp-login                                         # Run only login tests
mvn test -pl otp-2fa -Dtest=EmailOtpAuthenticatorTest          # Run a single test class
mvn test -pl otp-2fa -Dtest=EmailOtpAuthenticatorTest#testActionSuccess  # Single test method
```

## Docker Development

```bash
docker compose up --build -d      # Build and start Keycloak + Mailpit
docker compose down -v            # Stop and remove volumes (fresh DB on next start)
docker compose logs keycloak      # View logs (SMS OTP codes appear here)
```

- Admin console: http://localhost:8080/admin/ (admin/admin)
- Mailpit UI: http://localhost:8025/ (captures OTP emails)
- Test user: `testuser` / `password` (email: testuser@example.com, phone: +1234567890)
- Demo realm: `otp-demo` with pre-configured SMS OTP flows

## Architecture

### Module Dependencies

```
otp-2fa  ──→ common
otp-login ──→ common
themes (no Java dependencies)
```

**common** (`hr.delmisoft.keycloak.otp`) — shared infrastructure:
- `EmailOtpConst` / `SmsOtpConst` — constants (provider IDs, config keys, defaults, auth note keys, error codes)
- `OtpSendThrottle` — per-(realm, user, channel) send-cooldown helper, backed by `SingleUseObjectProvider.putIfAbsent` (cluster-safe)
- Custom SMS SPI: `SmsProvider` / `SmsProviderFactory` / `SmsSpi` with `LogSmsSenderFactory` default
- SPI registrations: `org.keycloak.provider.Spi`, `hr.delmisoft.keycloak.otp.sms.SmsProviderFactory`

**otp-2fa** — browser flow authenticators (2FA after password):
- `EmailOtpAuthenticator` / `EmailOtpAuthenticatorFactory` — email OTP form
- `SmsOtpAuthenticator` / `SmsOtpAuthenticatorFactory` — SMS OTP form
- `OtpChannelChoiceAuthenticator` / `OtpChannelChoiceAuthenticatorFactory` — combined channel selection + OTP form (user picks email or SMS)
- Stores OTP state in `AuthenticationSessionModel` auth notes

**otp-login** — custom OAuth2 grant types for OTP login:
- `EmailOtpGrantType` / `SmsOtpGrantType` (`urn:otp:email`, `urn:otp:sms`)
  - Self-contained two-phase OTP flow at the token endpoint
  - Optional password validation (MFA when password present, passwordless when absent)
  - Registered via `META-INF/services/org.keycloak.protocol.oidc.grants.OAuth2GrantTypeFactory`
- Uses `SingleUseObjectProvider` for stateless token-based OTP sessions
- Phase-1 delivery is **asynchronous**: the request stores the OTP session and enlists an after-completion hook (`session.getTransactionManager().enlistAfterCompletion`); after the request transaction commits, the hook submits the send to `ExecutorsProvider.getExecutor("otp-delivery")`, which runs it via `KeycloakModelUtils.runJobInTransaction` in a fresh session, re-resolving realm/user by id. `sendOtp(KeycloakSession, RealmModel, UserModel, code)` must use only its arguments, never the grant's request-scoped fields. Async failure (or a rolled-back request) is logged and rolled back: OTP session removed, per-user / identifier / IP slots released. Phase 1 never returns `500 otp_send_failed` any more; the client sees `*OtpSessionExpired` in phase 2 and may retry phase 1 immediately

**themes** — pure resources, no Java code:
- `theme/otp/login/` — login form templates (`login-email-otp.ftl`, `login-sms-otp.ftl`, `login-otp-channel-select.ftl`) + messages
  - Extends `keycloak.v2` theme (PatternFly v5, uses `field.ftl`/`buttons.ftl` macros)
- `theme/otp/email/` — email templates for OTP codes (html + text) + messages
  - Extends `base` theme
- Registered via `META-INF/keycloak-themes.json` as theme name `otp`

### Key Design Patterns

- OTP codes use constant-time comparison (`MessageDigest.isEqual`) to prevent timing attacks
- Codes are generated with `SecureRandom`
- All authenticators are configurable (code length, TTL, max retries, send cooldown) via Keycloak's authenticator config
- Browser `authenticate()` is idempotent: refreshing the OTP page rehydrates the existing valid code instead of triggering a new send
- **Send rate limiting** — `OtpSendThrottle` keyed by `(realmId, userId, channel)`:
  - Browser flow: initial send for a fresh auth session always goes through; explicit **Resend** button and expired-code resends are gated by `sendCooldown` (default 60s)
  - Grant types (`urn:otp:email`/`urn:otp:sms`): every phase-1 request is gated by a **per-(realm, submitted identifier, channel)** slot (`OtpSendThrottle.tryReserveForIdentifier`, key = SHA-256 of the trimmed, lower-cased username/email) *before* the user is looked up, so unknown usernames are throttled exactly like real ones. Throttled requests return **HTTP 429** with `Retry-After` header and JSON body `{error:"otp_send_throttled", retry_after:N}`. The per-user slot still caps real sends; when only it blocks (e.g. same account via email after username) the grant returns the normal fake phase-1 401 instead of 429. Cooldown read from realm attribute `otp.sendCooldown` (default 60s).
- **Per-source-IP send limit**: `OtpSendThrottle.tryReserveIpSlot` / `releaseIpSlot`, keyed by `(realmId, client IP)` across all users and both channels (anti SMS-pumping / bombing):
  - Realm attributes `otp.ipSendLimit` (default 10, `0` disables) and `otp.ipSendWindow` (default 3600s)
  - Cluster-safe: one of N numbered slot keys `otp-ip:{realm}:{ip}:{slot}` is reserved with `putIfAbsent` and the window as TTL (no read-modify-write counter)
  - IP from `ClientConnection.getRemoteAddr()` (honors Keycloak proxy config); IPv6 grouped by /64; missing IP is not tracked
  - Checked **before** the identifier/per-user cooldowns. Browser: slot released when the per-user cooldown blocks or delivery fails. Grant types: slot released when the identifier throttle blocks (429) or delivery fails; kept when only the per-user cooldown blocks, so that case matches the fake path
  - Grant types: same 429 shape as the cooldown. Unknown/disabled/unverified usernames also consume a slot (no enumeration oracle)
  - Browser: OTP form rendered without sending, error message key `otpSendIpLimited`
- **Grant-type account-enumeration resistance** (`AbstractOtpGrantType`): unknown / disabled / unverified / brute-force-locked / required-actions users and wrong `password` all get the indistinguishable phase-1 response (401 `*_otp_required` + random never-stored `otp_session_id`, no send; wrong password still records a brute-force failure). Every phase-2 failure that could depend on the account (ineligible user, wrong password, unknown/expired session, session bound to another user) returns the same 401 `*OtpSessionExpired` "OTP session has expired" response and consumes the submitted session id. Code generation/hashing, a dummy password hash and throwaway 1s cache writes (`otp-decoy:*`, same count as a real send) run on the fake path; delivery is asynchronous, so SMTP/SMS latency never reaches the response time. Residual: the account lookup itself and a few cache operations. `OtpGrantEnumerationParityTest` asserts real-vs-unknown parity — keep it passing when touching the grant flow.
- **Per-code attempt limit (browser flow)** — `maxRetries` is enforced per *delivered code*, not per auth session. Before verifying, authenticators call `OtpSendThrottle.tryConsumeAttempt(...)`, which atomically reserves one of `maxRetries` numbered slot keys (`otp-throttle:{realm}:{user}:{channel}:attempt:{codeHash}:{n}`, via `putIfAbsent`, TTL = code expiry) shared by all sessions. When a code runs out of attempts, `OtpSendThrottle.burnCode(...)` drops it from the recoverable stash so `getRecentCode` returns null. Resend / channel re-select / a restarted login within the cooldown therefore never restores guesses; a new code is only sent once the cooldown allows. A legitimate restart within the cooldown still recovers an un-burned code (with its remaining attempts).
- **Per-code attempt limit (grant types)** — phase 2 uses the same `tryConsumeAttempt` slots (keyed on the code hash, `DEFAULT_MAX_RETRIES` = 3, TTL = `codeExpiresAt` session note) *before* verifying, so concurrent guesses against one `otp_session_id` can never evaluate more than 3 wrong codes, and grant and browser guesses on a grant-sent code share one budget (the effective total is the larger of the two configured limits). The last wrong guess burns the stash; the next request finds no slot, removes the OTP session and gets `*OtpMaxRetries`. A correct code is redeemed only if `store.remove(otp_session_id)` returns the entry (one token per session under concurrency) and then burned so the browser flow cannot recover it.

### Testing

**Unit tests** live alongside each module (`common/src/test/`, `otp-2fa/src/test/`, `otp-login/src/test/`). JUnit 5 + Mockito mocking Keycloak's session/realm/user model interfaces.

**E2E tests** in `e2e/` use Playwright (Chromium) against a running Docker instance.

Two ways to run them:

```bash
# Direct (requires you to `docker compose up` first):
cd e2e && npm test                           # Run all E2E tests
cd e2e && npm run test:sms                   # SMS OTP tests only
cd e2e && npm run test:headed                # Run with visible browser

# Maven-integrated (handles docker compose up/down automatically):
mvn verify -P e2e                            # Unit tests + docker up + Playwright + docker down
```

The `e2e` Maven module (activated by the `-P e2e` profile) is wired into the standard `pre-integration-test` → `integration-test` → `post-integration-test` → `verify` lifecycle via `maven-antrun-plugin`: it brings up `docker compose`, polls until Keycloak is reachable, runs `npx playwright test`, then tears the stack down regardless of test outcome. A failing test run propagates as a Maven build failure via a recorded exit code in `e2e/target/e2e-exit-code.txt`.

> The demo realm sets `sendCooldown=5s` (and `otp.sendCooldown=5s` for grant types). Long enough that slow CI render delay can't burn through the cooldown before the OTP form is rendered (the disabled-resend-button assertion was flaking at 2s), short enough that the resend E2E tests still exercise the throttled-then-allowed transitions without long waits.

> The whole E2E suite sends every OTP from a single client IP, so the demo realm sets `otp.ipSendLimit=1000` / `otp.ipSendWindow=60` — high enough that the suite never trips the per-IP limit, while still exercising the slot-reservation path against real Keycloak. `otp-ip-limit.spec.js` temporarily lowers the limit via the admin API to assert the 429, then restores the original realm attributes.

E2E tests extract SMS OTP codes from Docker logs (`LogSmsSenderFactory` output) and email OTP codes from Mailpit API.

## CI Pipeline

GitHub Actions workflow (`.github/workflows/ci.yml`):
- **build**: `mvn clean verify`, uploads `dist/target/keycloak-otp-*.jar` as artifact
- **security**: SpotBugs + Find Security Bugs, OWASP Dependency-Check
- **release**: on `v*` tag push, creates GitHub Release with the single JAR

Security plugins configured in parent `pom.xml` (`pluginManagement`):
- `spotbugs-maven-plugin` with `findsecbugs-plugin` — run via `mvn compile spotbugs:check`
- `dependency-check-maven` — run via `mvn dependency-check:aggregate`
- SpotBugs exclusion filter: `spotbugs-exclude.xml`
- Suppressions file: `dependency-check-suppressions.xml`
