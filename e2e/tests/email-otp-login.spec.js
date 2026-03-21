const { test, expect } = require('@playwright/test');
const {
  TEST_USER,
  KEYCLOAK_URL,
  REALM,
  getSmsOtpCodeFromLogs,
  clearMailpit,
} = require('./helpers');

// The otp-demo-client uses the realm default browser flow (passwordless SMS OTP).
// To test the email OTP flow we'd need a client with a flow override.
// These tests verify the OTP login via the otp-demo-client works end-to-end.

const REDIRECT_URI = encodeURIComponent(`${KEYCLOAK_URL}/realms/${REALM}/account/`);
const CLIENT_LOGIN_URL =
  `${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/auth` +
  `?client_id=otp-demo-client&response_type=code&scope=openid&redirect_uri=${REDIRECT_URI}`;

test.describe('OTP browser login via otp-demo-client', () => {
  // Run serially to avoid OTP code conflicts with other tests
  test.describe.configure({ mode: 'serial' });

  test.beforeEach(async ({ page }) => {
    await clearMailpit(page);
  });

  test('should complete OTP login flow via otp-demo-client', async ({ page }) => {
    // 1. Navigate to login via otp-demo-client
    await page.goto(CLIENT_LOGIN_URL);
    await page.waitForSelector('#username', { timeout: 15_000 });

    // 2. Enter username (realm default is passwordless SMS OTP)
    await page.fill('#username', TEST_USER);
    await page.click('#kc-login');

    // 3. Wait for the OTP form
    await page.waitForSelector('#kc-sms-otp-form', { timeout: 15_000 });

    // 4. Get OTP and submit
    const otpCode = await getSmsOtpCodeFromLogs();
    expect(otpCode).toMatch(/^\d{6}$/);
    await page.fill('#otp', otpCode);
    await page.click('#kc-login');

    // 5. Should redirect away from login — either to redirect_uri or with auth code
    await page.waitForURL((url) => !url.pathname.includes('/login-actions/'), {
      timeout: 15_000,
    });
    const finalUrl = page.url();
    expect(finalUrl).not.toContain('/login-actions/authenticate');
  });

  test('should reject invalid OTP code via otp-demo-client', async ({ page }) => {
    await page.goto(CLIENT_LOGIN_URL);
    await page.waitForSelector('#username', { timeout: 15_000 });

    await page.fill('#username', TEST_USER);
    await page.click('#kc-login');

    await page.waitForSelector('#kc-sms-otp-form', { timeout: 15_000 });

    // Enter wrong OTP
    await page.fill('#otp', '999999');
    await page.click('#kc-login');

    // Should stay on OTP form with error
    await page.waitForSelector('#kc-sms-otp-form', { timeout: 10_000 });
    const errorVisible = await page
      .locator('.pf-m-danger, .kc-feedback-text, #input-error-otp-code, .alert-error')
      .first()
      .isVisible();
    expect(errorVisible).toBe(true);
  });
});
