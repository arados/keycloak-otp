# Keycloak Email & SMS OTP Authenticator

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

A Keycloak SPI plugin that adds one-time password (OTP) authentication via **email** and **SMS**. Supports browser login flows and custom OAuth2 grant types for API-based authentication.

> [!NOTE]
> This was developed using Claude Code. It is also still work in progress.

## Requirements

- Java 17+
- Keycloak 26.x (built against 26.5.5)
- Maven 3.x

## Project Structure

This is a multi-module Maven project:

| Module | Artifact | Description |
|---|---|---|
| `common/` | `keycloak-otp-common` | Shared constants, SMS SPI interfaces and default log provider |
| `otp-2fa/` | `keycloak-otp-2fa` | Browser flow authenticators for 2FA (email + SMS OTP forms) |
| `otp-login/` | `keycloak-otp-login` | Custom OAuth2 grant types for OTP login via token endpoint |
| `themes/` | `keycloak-otp-themes` | FreeMarker templates, messages, and theme resources |
| `dist/` | `keycloak-otp` | Single deployable JAR (all modules merged) |

## Build

```bash
mvn clean package
```

Produces a single deployable JAR:
- `dist/target/keycloak-otp-1.0.0-SNAPSHOT.jar`

Or download a pre-built JAR from [GitHub Releases](https://github.com/arados/keycloak-otp/releases).

## Installation

Copy the single JAR into Keycloak's `providers/` directory:

```bash
cp dist/target/keycloak-otp-1.0.0-SNAPSHOT.jar /opt/keycloak/providers/
```

Then rebuild Keycloak (required after adding providers):

```bash
/opt/keycloak/bin/kc.sh build
```

Restart Keycloak after the build completes.

## Docker Development

A Docker Compose setup is included for local development:

```bash
docker compose up --build -d    # Build and start
docker compose logs keycloak    # View logs (SMS OTP codes appear here)
docker compose down -v          # Stop and wipe data
```

Services:
- **Keycloak**: http://localhost:8080 — admin console at `/admin/` (admin/admin)
- **Mailpit**: http://localhost:8025 — captures OTP emails

A pre-configured `otp-demo` realm is imported with:
- Browser OTP flows (SMS, email, and channel choice)
- The `otp` login/email theme enabled
- Passwordless SMS OTP browser flow bound as realm default
- Client `otp-demo-client`: password + OTP (MFA)
- Client `passwordless-demo-client`: username + OTP only (no password)
- Test user: `testuser` / `password` (email: testuser@example.com, phone: +1234567890)

## Authenticators Provided

| Provider ID | Display Name | Flow Type | Channel |
|---|---|---|---|
| `email-otp-form` | Email OTP Form | Browser | Email |
| `sms-otp-form` | SMS OTP Form | Browser | SMS |
| `otp-channel-choice-form` | OTP Channel Choice | Browser | Email or SMS |
| `urn:otp:email` | Email OTP Grant | Custom Grant Type | Email |
| `urn:otp:sms` | SMS OTP Grant | Custom Grant Type | SMS |

## Theme

The `themes/` module provides a Keycloak theme named `otp`. It includes:

- **Login type**: OTP input forms (`login-email-otp.ftl`, `login-sms-otp.ftl`, `login-otp-channel-select.ftl`) and i18n messages — extends the `keycloak.v2` theme (PatternFly v5, uses `field.ftl`/`buttons.ftl` macros)
- **Email type**: OTP code email templates (HTML + text) and i18n messages — extends the `base` theme

To use the theme, set `loginTheme` and/or `emailTheme` to `otp` in the realm settings.

## Configuration Options

All authenticators are configurable through the Keycloak admin console under the execution's config:

### Email OTP

| Config Key | Label | Default | Description |
|---|---|---|---|
| `emailOtp.codeLength` | Code Length | `6` | Number of digits in the OTP code |
| `emailOtp.ttl` | Code TTL (seconds) | `300` | Time-to-live for the OTP code |
| `emailOtp.maxRetries` | Max Retries | `3` | Max failed attempts before invalidation |

### SMS OTP

| Config Key | Label | Default | Description |
|---|---|---|---|
| `smsOtp.codeLength` | Code Length | `6` | Number of digits in the OTP code |
| `smsOtp.ttl` | Code TTL (seconds) | `300` | Time-to-live for the OTP code |
| `smsOtp.maxRetries` | Max Retries | `3` | Max failed attempts before invalidation |
| `smsOtp.phoneAttribute` | Phone Number Attribute | `phoneNumber` | User attribute storing the phone number |

## Setup: Browser Flow

1. In the Keycloak admin console, go to **Authentication** > **Flows**.
2. Copy the **Browser** flow (or create a new one).
3. Add an execution and select **Email OTP Form** or **SMS OTP Form**.
4. Set the requirement to **Required** (or **Conditional**).
5. Optionally click the gear icon to configure code length, TTL, and max retries.
6. Bind the flow to the browser flow in **Authentication** > **Bindings**.
7. Set the realm's login theme to `otp` under **Realm Settings** > **Themes**.

After login with username/password, the user will be prompted to enter the OTP code sent to their email or phone.

## Custom Grant Types (Recommended)

The plugin provides custom OAuth2 grant types that replace `grant_type=password` with dedicated, descriptive grant types. The `password` parameter is **optional** — include it for MFA (password + OTP), omit it for passwordless (OTP only).

| Grant Type | Channel | Description |
|---|---|---|
| `urn:otp:email` | Email | Email OTP authentication |
| `urn:otp:sms` | SMS | SMS OTP authentication |

No flow configuration is needed — the grant types are self-contained.

### API Usage

**Phase 1 — Request the OTP:**

```bash
# Passwordless (OTP only)
curl -X POST "${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/token" \
  -d "grant_type=urn:otp:sms" \
  -d "client_id=${CLIENT_ID}" \
  -d "username=${USERNAME}"

# MFA (password + OTP) — same grant type, just add password
curl -X POST "${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/token" \
  -d "grant_type=urn:otp:email" \
  -d "client_id=${CLIENT_ID}" \
  -d "username=${USERNAME}" \
  -d "password=${PASSWORD}"
```

Response (HTTP 401):

```json
{
  "error": "sms_otp_required",
  "error_description": "An OTP code has been sent to your phone number.",
  "otp_session_id": "a1b2c3d4-..."
}
```

**Phase 2 — Submit the OTP:**

```bash
curl -X POST "${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/token" \
  -d "grant_type=urn:otp:sms" \
  -d "client_id=${CLIENT_ID}" \
  -d "username=${USERNAME}" \
  -d "otp=${OTP_CODE}" \
  -d "otp_session_id=${OTP_SESSION_ID}"
```

On success, returns the standard token response with `access_token`, `refresh_token`, etc.

## Passwordless Authentication

The same authenticators support passwordless login — the user provides only a username, then verifies via OTP.

### Passwordless Browser Flow

Uses Keycloak's built-in `auth-username-form` (username only, no password) followed by the OTP step:

```
auth-cookie                    (ALTERNATIVE)
passwordless-forms             (ALTERNATIVE)
  ├── auth-username-form       (REQUIRED)   ← username only
  └── sms-otp-form             (REQUIRED)   ← OTP replaces password
```

To configure manually:
1. Create a new browser flow.
2. Add `auth-cookie` as ALTERNATIVE.
3. Add a sub-flow (ALTERNATIVE) with `Username Form` (REQUIRED) then `SMS OTP Form` or `Email OTP Form` (REQUIRED).
4. Bind the flow to the realm or client.

### Passwordless Direct Grant

With custom grant types, simply omit the `password` parameter — no separate flow needed. See [Custom Grant Types](#custom-grant-types-recommended).

### Pre-configured Flows in Demo Realm

The `otp-demo` realm includes browser flow variants:

| Flow Alias | Type | Mode |
|---|---|---|
| `browser-with-email-otp` | Browser | Password + Email OTP |
| `browser-with-sms-otp` | Browser | Password + SMS OTP |
| `passwordless-browser-email-otp` | Browser | Username + Email OTP |
| `passwordless-browser-sms-otp` | Browser | Username + SMS OTP |
| `browser-otp-choice` | Browser | Password + Email **or** SMS OTP (user chooses) |

For direct grant (API) usage, use the custom grant types `urn:otp:email` and `urn:otp:sms` — no flow configuration needed.

## Setup: OTP Channel Choice Flow

The **OTP Channel Choice** authenticator presents a single screen where the user selects between email and SMS OTP, then enters the code — all within one authenticator execution.

```
auth-cookie                        (ALTERNATIVE)
browser-otp-choice-forms           (ALTERNATIVE)
  ├── auth-username-password-form  (REQUIRED)
  └── otp-channel-choice-form      (REQUIRED)
```

### OTP Channel Choice Configuration

| Config Key | Label | Default | Description |
|---|---|---|---|
| `otpChoice.codeLength` | Code Length | `6` | Number of digits in the OTP code |
| `otpChoice.ttl` | Code TTL (seconds) | `300` | Time-to-live for the OTP code |
| `otpChoice.maxRetries` | Max Retries | `3` | Max failed attempts before invalidation |
| `otpChoice.phoneAttribute` | Phone Number Attribute | `phoneNumber` | User attribute storing the phone number |

## Email Configuration

Email OTP uses Keycloak's built-in email provider. Configure SMTP settings in the admin console under **Realm Settings** > **Email**. No additional configuration is needed for the email channel beyond standard Keycloak SMTP setup.

## SMS Provider SPI

SMS sending is pluggable via a custom SPI. The plugin ships with a **log** provider (`LogSmsSenderFactory`) that logs SMS messages to the Keycloak server log instead of sending them — useful for development and testing.

### Using the Log Provider

The log provider is active by default. OTP codes will appear in the Keycloak server log:

```
INFO  [hr.delmisoft.keycloak.otp.sms.LogSmsSenderFactory] SMS to +1234567890: Your verification code is: 123456
```

### Implementing a Custom SMS Provider

To integrate with a real SMS gateway (e.g., Twilio, AWS SNS), implement two interfaces:

1. **`SmsProvider`** — the send logic:

```java
public class TwilioSmsProvider implements SmsProvider {
    @Override
    public void send(String phoneNumber, String message) throws SmsException {
        // Call Twilio API
    }

    @Override
    public void close() {}
}
```

2. **`SmsProviderFactory`** — the factory:

```java
public class TwilioSmsProviderFactory implements SmsProviderFactory {
    @Override
    public SmsProvider create(KeycloakSession session) {
        return new TwilioSmsProvider();
    }

    @Override
    public String getId() {
        return "twilio";
    }

    @Override
    public void init(Config.Scope config) {}

    @Override
    public void postInit(KeycloakSessionFactory factory) {}

    @Override
    public void close() {}
}
```

3. Register the factory in `META-INF/services/hr.delmisoft.keycloak.otp.sms.SmsProviderFactory`:

```
hr.delmisoft.TwilioSmsProviderFactory
```

4. Select the provider in Keycloak's configuration:

```bash
/opt/keycloak/bin/kc.sh start --spi-sms-provider=twilio
```

### SMS User Setup

Users must have a phone number stored in the user attribute specified by the `smsOtp.phoneAttribute` config (default: `phoneNumber`). Set this attribute in the admin console under **Users** > select user > **Attributes**, or via the Keycloak Admin REST API.

## Running Tests

### Unit Tests

```bash
mvn test                    # Run all tests
mvn test -pl common         # Run only common tests
mvn test -pl otp-2fa        # Run only 2FA tests
mvn test -pl otp-login      # Run only login tests
```

Unit tests use JUnit 5 and Mockito to test authenticator logic against mocked Keycloak interfaces.

### E2E Tests (Playwright)

Browser-based integration tests that verify the full OTP login flow against a running Keycloak instance.

```bash
cd e2e
npm install
npx playwright install chromium
npm test                    # Run all E2E tests
npm run test:sms            # Run SMS OTP tests only
npm run test:headed         # Run with visible browser
```

Requires Docker services to be running (`docker compose up --build -d`). Tests cover:
- SMS OTP login flow (form rendering, valid/invalid codes, post-login account access)
- OTP login via custom client (`otp-demo-client`)
- OTP channel choice flow (email or SMS selection)

## Security

> **Warning**: The Docker Compose setup and `otp-demo` realm are for **development and testing only**. They use hardcoded credentials (`admin/admin`, `testuser/password`) and the log-based SMS provider. Do not use these in production.

- OTP codes are compared using constant-time comparison (`MessageDigest.isEqual`) to prevent timing attacks
- Codes are generated with `SecureRandom`
- OTP sessions are stored in Keycloak's `SingleUseObjectProvider` (custom grant types) or `AuthenticationSessionModel` auth notes (browser flow)
- Brute-force protection is built in via configurable max retries

## License

This project is licensed under the [Apache License 2.0](LICENSE).
