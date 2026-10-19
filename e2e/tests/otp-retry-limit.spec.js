const { test, expect } = require('@playwright/test');
const { execSync } = require('child_process');
const path = require('path');
const {
  TEST_USER,
  accountConsoleUrl,
  getSmsOtpCodeFromLogs,
} = require('./helpers');

const PROJECT_ROOT = path.resolve(__dirname, '../..');

const INVALID_TEXT = /Invalid code/;
const MAX_RETRIES_TEXT = /Too many failed attempts/;

function countSmsSends() {
  const logs = execSync('docker compose logs keycloak 2>&1', {
    cwd: PROJECT_ROOT,
    encoding: 'utf-8',
  });
  return (logs.match(/Your verification code is:\s*\d{6}/g) || []).length;
}

function wrongCodeFor(code) {
  const last = code[code.length - 1];
  return code.slice(0, -1) + (last === '9' ? '0' : String(Number(last) + 1));
}

async function startSmsLogin(page) {
  await page.goto(accountConsoleUrl());
  await page.waitForSelector('#username', { timeout: 15_000 });
  await page.fill('#username', TEST_USER);
  await page.click('#kc-login');
  await page.waitForSelector('#kc-sms-otp-form', { timeout: 15_000 });
}

function isFormPost(resp) {
  const req = resp.request();
  return req.isNavigationRequest() && req.method() === 'POST';
}

async function submitOtp(page, code) {
  await page.fill('#otp', code);
  await Promise.all([
    page.waitForResponse(isFormPost),
    page.click('#kc-login'),
  ]);
  await page.waitForLoadState('domcontentloaded');
}

async function expectFormError(page, pattern) {
  await page.waitForSelector('#kc-sms-otp-form', { timeout: 10_000 });
  await expect(page.locator('body')).toContainText(pattern);
}

test.describe('OTP retry limit cannot be bypassed (passwordless SMS flow, maxRetries=3, cooldown=5s)', () => {
  test.describe.configure({ mode: 'serial' });

  test('Resend within cooldown does not grant more guesses and the burned code no longer logs in', async ({ page, browser }) => {
    // Start outside any cooldown left over from earlier specs so this login delivers a fresh code.
    await page.waitForTimeout(7_000);

    await startSmsLogin(page);
    const code = await getSmsOtpCodeFromLogs();
    expect(code).toMatch(/^\d{6}$/);
    const wrong = wrongCodeFor(code);
    const sendsAfterFirstSend = countSmsSends();

    // Burn the code: 3 wrong guesses, then the 4th is rejected with max-retries.
    for (let i = 0; i < 3; i++) {
      await submitOtp(page, wrong);
      await expectFormError(page, INVALID_TEXT);
    }
    await submitOtp(page, wrong);
    await expectFormError(page, MAX_RETRIES_TEXT);

    // Attack step: POST resend=true while the cooldown is still active. The button is disabled
    // client-side, so submit the form directly the way an attacker would.
    await Promise.all([
      page.waitForResponse(isFormPost),
      page.evaluate(() => document.getElementById('kc-otp-resend-form').submit()),
    ]);
    await page.waitForLoadState('domcontentloaded');
    await page.waitForSelector('#kc-sms-otp-form', { timeout: 10_000 });
    // Still inside the cooldown: no new SMS was sent, so this is the same code.
    expect(countSmsSends()).toBe(sendsAfterFirstSend);

    // The attempt budget must NOT have been restored.
    await submitOtp(page, wrong);
    await expectFormError(page, MAX_RETRIES_TEXT);

    // Even the real code is rejected now — it has been burned.
    await submitOtp(page, code);
    await expectFormError(page, MAX_RETRIES_TEXT);
    expect(page.url()).not.toMatch(/\/realms\/otp-demo\/account\/?(#.*)?$/);

    // A brand-new auth session (fresh cookies) must not be able to use the burned code either.
    const context2 = await browser.newContext();
    const page2 = await context2.newPage();
    try {
      await startSmsLogin(page2);
      await submitOtp(page2, code);
      await page2.waitForSelector('#kc-sms-otp-form', { timeout: 10_000 });
      expect(page2.url()).not.toMatch(/\/realms\/otp-demo\/account\/?(#.*)?$/);
    } finally {
      await context2.close();
    }

    // Let the cooldown elapse so later specs get a fresh, un-burned code.
    await page.waitForTimeout(6_000);
  });
});
