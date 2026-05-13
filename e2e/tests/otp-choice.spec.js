const { test, expect } = require('@playwright/test');
const {
  TEST_USER,
  KEYCLOAK_URL,
  REALM,
  getSmsOtpCodeFromLogs,
  getEmailOtpCode,
  clearMailpit,
} = require('./helpers');

test.describe('OTP channel selection (Email vs SMS)', () => {
  test.describe.configure({ mode: 'serial' });

  let adminToken;

  test.beforeAll(async ({ request }) => {
    const tokenRes = await request.post(`${KEYCLOAK_URL}/realms/master/protocol/openid-connect/token`, {
      form: {
        client_id: 'admin-cli',
        username: 'admin',
        password: 'admin',
        grant_type: 'password',
      },
    });
    const tokenData = await tokenRes.json();
    adminToken = tokenData.access_token;

    // Set realm browser flow to browser-otp-choice
    await request.put(`${KEYCLOAK_URL}/admin/realms/${REALM}`, {
      headers: { Authorization: `Bearer ${adminToken}` },
      data: { browserFlow: 'browser-otp-choice' },
    });
  });

  test.afterAll(async ({ request }) => {
    const tokenRes = await request.post(`${KEYCLOAK_URL}/realms/master/protocol/openid-connect/token`, {
      form: {
        client_id: 'admin-cli',
        username: 'admin',
        password: 'admin',
        grant_type: 'password',
      },
    });
    const tokenData = await tokenRes.json();
    await request.put(`${KEYCLOAK_URL}/admin/realms/${REALM}`, {
      headers: { Authorization: `Bearer ${tokenData.access_token}` },
      data: { browserFlow: 'passwordless-browser-sms-otp' },
    });
  });

  test('should show channel selection screen after username', async ({ page }) => {
    await page.goto(`${KEYCLOAK_URL}/realms/${REALM}/account`);
    await page.waitForSelector('#username', { timeout: 15_000 });

    await page.fill('#username', TEST_USER);
    await page.click('#kc-login');

    // Should see the channel selection form
    await page.waitForSelector('#kc-otp-channel-select-form', { timeout: 15_000 });

    // Verify both options are present
    const emailButton = page.locator('button[value="email"]');
    const smsButton = page.locator('button[value="sms"]');
    await expect(emailButton).toBeVisible();
    await expect(smsButton).toBeVisible();

    // Verify text content
    const bodyText = await page.textContent('body');
    expect(bodyText).toContain('Email');
    expect(bodyText).toContain('SMS');
  });

  test('should complete login after choosing SMS', async ({ page }) => {
    const networkFailures = [];
    page.on('response', (response) => {
      if (response.status() === 401 && response.url().includes('/account')) {
        networkFailures.push({ url: response.url(), status: response.status() });
      }
    });

    await page.goto(`${KEYCLOAK_URL}/realms/${REALM}/account`);
    await page.waitForSelector('#username', { timeout: 15_000 });
    await page.fill('#username', TEST_USER);
    await page.click('#kc-login');

    // Wait for channel selection
    await page.waitForSelector('#kc-otp-channel-select-form', { timeout: 15_000 });

    // Click SMS
    await page.click('button[value="sms"]');

    // Should show SMS OTP form
    await page.waitForSelector('#kc-sms-otp-form', { timeout: 15_000 });

    // Get and enter OTP
    const otpCode = await getSmsOtpCodeFromLogs();
    await page.fill('#otp', otpCode);
    await page.click('#kc-login');

    // Should redirect to account console
    await page.waitForURL(/\/realms\/otp-demo\/account/, { timeout: 15_000 });
    await page.waitForLoadState('networkidle');

    // No 401 errors
    expect(networkFailures).toEqual([]);
  });

  test('should complete login after choosing Email', async ({ page, context }) => {
    await context.clearCookies();
    await clearMailpit(page);

    await page.goto(`${KEYCLOAK_URL}/realms/${REALM}/account`);
    await page.waitForSelector('#username', { timeout: 15_000 });
    await page.fill('#username', TEST_USER);
    await page.click('#kc-login');

    // Wait for channel selection
    await page.waitForSelector('#kc-otp-channel-select-form', { timeout: 15_000 });

    // Click Email
    await page.click('button[value="email"]');

    // Should show Email OTP form
    await page.waitForSelector('#kc-email-otp-form', { timeout: 15_000 });

    // Get OTP from Mailpit
    const otpCode = await getEmailOtpCode(page);
    expect(otpCode).toMatch(/^\d{6}$/);
    await page.fill('#otp', otpCode);
    await page.click('#kc-login');

    // Should redirect to account console
    await page.waitForURL(/\/realms\/otp-demo\/account/, { timeout: 15_000 });
  });

  test('should allow switching channel after browser back (SMS → Email)', async ({ page, context }) => {
    // The previous test sent an email, so the per-(realm, user, email) cooldown may still be
    // active when this test's email click hits the server. Wait past the demo realm's 2s
    // cooldown so the helper's Mailpit poll observes a fresh email rather than timing out.
    await page.waitForTimeout(2500);

    await context.clearCookies();
    await clearMailpit(page);

    await page.goto(`${KEYCLOAK_URL}/realms/${REALM}/account`);
    await page.waitForSelector('#username', { timeout: 15_000 });
    await page.fill('#username', TEST_USER);
    await page.click('#kc-login');

    // Select SMS first
    await page.waitForSelector('#kc-otp-channel-select-form', { timeout: 15_000 });
    await page.click('button[value="sms"]');
    await page.waitForSelector('#kc-sms-otp-form', { timeout: 15_000 });

    // Press browser back to return to channel selection
    await page.goBack();
    await page.waitForSelector('#kc-otp-channel-select-form', { timeout: 15_000 });

    // Now select Email instead
    await page.click('button[value="email"]');
    await page.waitForSelector('#kc-email-otp-form', { timeout: 15_000 });

    // Get OTP from Mailpit and complete login
    const otpCode = await getEmailOtpCode(page);
    expect(otpCode).toMatch(/^\d{6}$/);
    await page.fill('#otp', otpCode);
    await page.click('#kc-login');

    await page.waitForURL(/\/realms\/otp-demo\/account/, { timeout: 15_000 });
  });

  test('should allow switching channel after browser back (Email → SMS)', async ({ page, context }) => {
    // Wait past the email cooldown set by the previous test so this test's email click
    // gets a fresh send (the helper polls Mailpit, which doesn't see the throttle-stashed code).
    await page.waitForTimeout(2500);

    await context.clearCookies();
    await clearMailpit(page);

    await page.goto(`${KEYCLOAK_URL}/realms/${REALM}/account`);
    await page.waitForSelector('#username', { timeout: 15_000 });
    await page.fill('#username', TEST_USER);
    await page.click('#kc-login');

    // Select Email first
    await page.waitForSelector('#kc-otp-channel-select-form', { timeout: 15_000 });
    await page.click('button[value="email"]');
    await page.waitForSelector('#kc-email-otp-form', { timeout: 15_000 });

    // Press browser back to return to channel selection
    await page.goBack();
    await page.waitForSelector('#kc-otp-channel-select-form', { timeout: 15_000 });

    // Now select SMS instead
    await page.click('button[value="sms"]');
    await page.waitForSelector('#kc-sms-otp-form', { timeout: 15_000 });

    // Get OTP from logs and complete login
    const otpCode = await getSmsOtpCodeFromLogs();
    await page.fill('#otp', otpCode);
    await page.click('#kc-login');

    await page.waitForURL(/\/realms\/otp-demo\/account/, { timeout: 15_000 });
  });

  test('should reject invalid OTP after channel selection', async ({ page, context }) => {
    await context.clearCookies();
    await page.goto(`${KEYCLOAK_URL}/realms/${REALM}/account`);
    await page.waitForSelector('#username', { timeout: 15_000 });
    await page.fill('#username', TEST_USER);
    await page.click('#kc-login');

    await page.waitForSelector('#kc-otp-channel-select-form', { timeout: 15_000 });
    await page.click('button[value="sms"]');

    await page.waitForSelector('#kc-sms-otp-form', { timeout: 15_000 });

    // Enter wrong OTP
    await page.fill('#otp', '000000');
    await page.click('#kc-login');

    // Should stay on OTP form with error
    await page.waitForSelector('#kc-sms-otp-form', { timeout: 10_000 });
    const errorVisible = await page
      .locator('.pf-m-danger, .kc-feedback-text, #input-error-otp-code, .alert-error, .pf-m-error')
      .first()
      .isVisible();
    expect(errorVisible).toBe(true);
  });
});
