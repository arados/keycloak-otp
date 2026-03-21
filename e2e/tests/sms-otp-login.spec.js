const { test, expect } = require('@playwright/test');
const {
  TEST_USER,
  accountConsoleUrl,
  getSmsOtpCodeFromLogs,
  KEYCLOAK_URL,
  REALM,
} = require('./helpers');

test.describe('SMS OTP browser login (passwordless)', () => {
  test('should complete SMS OTP login and access account console without 401', async ({ page }) => {
    // Collect console errors and network failures
    const consoleErrors = [];
    page.on('console', (msg) => {
      if (msg.type() === 'error') consoleErrors.push(msg.text());
    });

    const networkFailures = [];
    page.on('response', (response) => {
      if (response.status() === 401) {
        networkFailures.push({ url: response.url(), status: response.status() });
      }
    });

    // 1. Navigate to account console — should redirect to login
    await page.goto(accountConsoleUrl());
    await page.waitForSelector('#username', { timeout: 15_000 });

    // 2. Enter username (passwordless flow — no password field)
    await page.fill('#username', TEST_USER);
    await page.click('#kc-login');

    // 3. Wait for the SMS OTP form
    await page.waitForSelector('#kc-sms-otp-form', { timeout: 15_000 });
    expect(await page.locator('#otp').isVisible()).toBe(true);

    // 4. Get the OTP code from Keycloak logs
    const otpCode = await getSmsOtpCodeFromLogs();
    expect(otpCode).toMatch(/^\d{6}$/);

    // 5. Enter OTP and submit
    await page.fill('#otp', otpCode);
    await page.click('#kc-login');

    // 6. Should be redirected to account console (not back to login)
    await page.waitForURL(/\/realms\/otp-demo\/account/, { timeout: 15_000 });

    // 7. Wait for account console to fully load
    await page.waitForLoadState('networkidle');

    // 8. Verify no 401 errors occurred after login
    const post401s = networkFailures.filter(
      (f) => !f.url.includes('/protocol/openid-connect/token')
    );
    expect(post401s).toEqual([]);

    // 9. Verify we're on the account console page (not an error page)
    const url = page.url();
    expect(url).toContain(`/realms/${REALM}/account`);

    // 10. The account console should show user info or personal-info section
    // The v3 account console is a SPA that renders after JS loads
    const bodyText = await page.textContent('body');
    expect(bodyText).toBeTruthy();
  });

  test('should reject invalid OTP code', async ({ page }) => {
    await page.goto(accountConsoleUrl());
    await page.waitForSelector('#username', { timeout: 15_000 });

    await page.fill('#username', TEST_USER);
    await page.click('#kc-login');

    await page.waitForSelector('#kc-sms-otp-form', { timeout: 15_000 });

    // Enter a wrong OTP code
    await page.fill('#otp', '000000');
    await page.click('#kc-login');

    // Should stay on the OTP form with an error message
    await page.waitForSelector('#kc-sms-otp-form', { timeout: 10_000 });
    const errorVisible = await page.locator('.pf-m-danger, .kc-feedback-text, #input-error-otp-code, .alert-error').first().isVisible();
    expect(errorVisible).toBe(true);
  });

  test('should show OTP form after username submission', async ({ page }) => {
    await page.goto(accountConsoleUrl());
    await page.waitForSelector('#username', { timeout: 15_000 });

    await page.fill('#username', TEST_USER);
    await page.click('#kc-login');

    // Verify the SMS OTP form elements
    await page.waitForSelector('#kc-sms-otp-form', { timeout: 15_000 });
    const otpInput = page.locator('#otp');
    expect(await otpInput.isVisible()).toBe(true);
    expect(await otpInput.getAttribute('autocomplete')).toBe('one-time-code');

    const submitButton = page.locator('#kc-login');
    expect(await submitButton.isVisible()).toBe(true);
  });
});

test.describe('SMS OTP post-login API access', () => {
  test('account API endpoints should return 200 after successful OTP login', async ({ page }) => {
    // Capture the Bearer token from the account console's API calls
    let bearerToken = null;
    page.on('request', (request) => {
      const auth = request.headers()['authorization'];
      if (auth && auth.startsWith('Bearer ') && request.url().includes('/account')) {
        bearerToken = auth;
      }
    });

    // Login first
    await page.goto(accountConsoleUrl());
    await page.waitForSelector('#username', { timeout: 15_000 });
    await page.fill('#username', TEST_USER);
    await page.click('#kc-login');
    await page.waitForSelector('#kc-sms-otp-form', { timeout: 15_000 });

    const otpCode = await getSmsOtpCodeFromLogs();
    await page.fill('#otp', otpCode);
    await page.click('#kc-login');

    await page.waitForURL(/\/realms\/otp-demo\/account/, { timeout: 15_000 });
    await page.waitForLoadState('networkidle');

    // Should have captured a Bearer token from the SPA's API calls
    expect(bearerToken).toBeTruthy();

    // Verify key account API endpoints respond with 200 using the captured token
    const endpoints = [
      `/realms/${REALM}/account/`,
      `/realms/${REALM}/account/supportedLocales`,
    ];

    for (const endpoint of endpoints) {
      const response = await page.request.get(`${KEYCLOAK_URL}${endpoint}`, {
        headers: {
          Accept: 'application/json',
          Authorization: bearerToken,
        },
      });
      expect(response.status(), `${endpoint} should return 200`).toBe(200);
    }
  });
});