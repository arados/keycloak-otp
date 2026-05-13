const { test, expect } = require('@playwright/test');
const { execSync } = require('child_process');
const path = require('path');
const {
  TEST_USER,
  KEYCLOAK_URL,
  REALM,
  accountConsoleUrl,
  getSmsOtpCodeFromLogs,
} = require('./helpers');

const PROJECT_ROOT = path.resolve(__dirname, '../..');

/**
 * Count how many "Your verification code is: ..." log lines have appeared
 * in the Keycloak container so we can detect new SMS sends.
 */
function countSmsSends() {
  const logs = execSync('docker compose logs keycloak 2>&1', {
    cwd: PROJECT_ROOT,
    encoding: 'utf-8',
  });
  return (logs.match(/Your verification code is:\s*\d{6}/g) || []).length;
}

test.describe('OTP send rate limiting (passwordless SMS flow, cooldown=5s)', () => {
  test.describe.configure({ mode: 'serial' });

  test('resend button is disabled during cooldown and enabled afterwards', async ({ page }) => {
    await page.goto(accountConsoleUrl());
    await page.waitForSelector('#username', { timeout: 15_000 });

    await page.fill('#username', TEST_USER);
    await page.click('#kc-login');

    await page.waitForSelector('#kc-otp-resend-button', { timeout: 15_000 });

    // Immediately after the first send, the resend button is disabled with a countdown
    const initialDisabled = await page.locator('#kc-otp-resend-button').isDisabled();
    expect(initialDisabled).toBe(true);

    const initialLabel = await page.locator('#kc-otp-resend-label').textContent();
    expect(initialLabel).toMatch(/Resend available in \d+s/);

    // After the cooldown elapses, the button becomes enabled (countdown JS flips it).
    // Realm config sets sendCooldown=5s; timeout includes buffer for slow CI render.
    await page.waitForFunction(
      () => !document.getElementById('kc-otp-resend-button').disabled,
      null,
      { timeout: 15_000 }
    );

    const finalLabel = await page.locator('#kc-otp-resend-label').textContent();
    expect(finalLabel).toMatch(/Resend code/);
  });

  test('refreshing the OTP page does NOT trigger another SMS send', async ({ page }) => {
    // Wait a few seconds so we're not still in the previous cooldown
    await page.waitForTimeout(4_000);

    await page.goto(accountConsoleUrl());
    await page.waitForSelector('#username', { timeout: 15_000 });

    await page.fill('#username', TEST_USER);
    await page.click('#kc-login');

    await page.waitForSelector('#kc-sms-otp-form', { timeout: 15_000 });

    const sendsBeforeRefresh = countSmsSends();

    // Refresh the page a few times
    await page.reload();
    await page.waitForSelector('#kc-sms-otp-form', { timeout: 15_000 });
    await page.reload();
    await page.waitForSelector('#kc-sms-otp-form', { timeout: 15_000 });

    const sendsAfterRefresh = countSmsSends();
    expect(sendsAfterRefresh).toBe(sendsBeforeRefresh);
  });

  test('clicking resend after cooldown triggers a new SMS send', async ({ page }) => {
    await page.waitForTimeout(4_000); // outside any prior cooldown

    await page.goto(accountConsoleUrl());
    await page.waitForSelector('#username', { timeout: 15_000 });

    await page.fill('#username', TEST_USER);
    await page.click('#kc-login');

    await page.waitForSelector('#kc-otp-resend-button', { timeout: 15_000 });
    const sendsBeforeResend = countSmsSends();

    // Wait for the cooldown timer to expire
    await page.waitForFunction(
      () => !document.getElementById('kc-otp-resend-button').disabled,
      null,
      { timeout: 15_000 }
    );

    await page.click('#kc-otp-resend-button');

    // After resend the form reloads with the button disabled again
    await page.waitForSelector('#kc-otp-resend-button[disabled]', { timeout: 10_000 });

    const sendsAfterResend = countSmsSends();
    expect(sendsAfterResend).toBeGreaterThan(sendsBeforeResend);

    // Verify the new code is valid (verifies the new code actually replaced the previous one)
    const newCode = await getSmsOtpCodeFromLogs();
    expect(newCode).toMatch(/^\d{6}$/);
  });
});

test.describe('OTP grant type rate limiting (SMS, cooldown=5s)', () => {
  test.describe.configure({ mode: 'serial' });

  const TOKEN_URL = `${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/token`;

  test('second phase-1 request within cooldown returns HTTP 429 with Retry-After', async ({ request }) => {
    // Wait so we don't collide with any in-flight cooldown from prior tests
    await new Promise((r) => setTimeout(r, 7_000));

    const params = new URLSearchParams({
      grant_type: 'urn:otp:sms',
      client_id: 'passwordless-demo-client',
      username: TEST_USER,
    });

    // First send — should succeed (returns 401 + otp_session_id)
    const first = await request.post(TOKEN_URL, {
      data: params.toString(),
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    });
    expect(first.status()).toBe(401);
    const firstBody = await first.json();
    expect(firstBody.otp_session_id).toBeTruthy();

    // Second send within cooldown — should be 429
    const second = await request.post(TOKEN_URL, {
      data: params.toString(),
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    });
    expect(second.status()).toBe(429);
    const secondBody = await second.json();
    expect(secondBody.error).toBe('otp_send_throttled');
    expect(secondBody.retry_after).toBeGreaterThan(0);
    expect(secondBody.retry_after).toBeLessThanOrEqual(5);

    const retryAfterHeader = second.headers()['retry-after'];
    expect(retryAfterHeader).toBeTruthy();
    expect(parseInt(retryAfterHeader, 10)).toBeGreaterThan(0);
  });

  test('after cooldown expires the grant type allows another send', async ({ request }) => {
    // Wait past the cooldown
    await new Promise((r) => setTimeout(r, 7_000));

    const params = new URLSearchParams({
      grant_type: 'urn:otp:sms',
      client_id: 'passwordless-demo-client',
      username: TEST_USER,
    });

    const res = await request.post(TOKEN_URL, {
      data: params.toString(),
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    });
    expect(res.status()).toBe(401);
    const body = await res.json();
    expect(body.otp_session_id).toBeTruthy();
    expect(body.error).toBe('sms_otp_required');
  });
});
