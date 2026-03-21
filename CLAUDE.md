# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Keycloak SPI plugin that adds OTP authentication via **email** and **SMS** channels. Multi-module Maven project producing a single deployable JAR.

- **Keycloak version**: 26.5.5
- **Java**: 17
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

**themes** — pure resources, no Java code:
- `theme/otp/login/` — login form templates (`login-email-otp.ftl`, `login-sms-otp.ftl`, `login-otp-channel-select.ftl`) + messages
  - Extends `keycloak.v2` theme (PatternFly v5, uses `field.ftl`/`buttons.ftl` macros)
- `theme/otp/email/` — email templates for OTP codes (html + text) + messages
  - Extends `base` theme
- Registered via `META-INF/keycloak-themes.json` as theme name `otp`

### Key Design Patterns

- OTP codes use constant-time comparison (`MessageDigest.isEqual`) to prevent timing attacks
- Codes are generated with `SecureRandom`
- All authenticators are configurable (code length, TTL, max retries) via Keycloak's authenticator config

### Testing

**Unit tests** live alongside each module (`common/src/test/`, `otp-2fa/src/test/`, `otp-login/src/test/`). JUnit 5 + Mockito mocking Keycloak's session/realm/user model interfaces.

**E2E tests** in `e2e/` use Playwright (Chromium) against a running Docker instance:

```bash
cd e2e && npm test                           # Run all E2E tests
cd e2e && npm run test:sms                   # SMS OTP tests only
cd e2e && npm run test:headed                # Run with visible browser
```

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
