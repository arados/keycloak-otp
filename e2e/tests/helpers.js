const KEYCLOAK_URL = 'http://localhost:8080';
const MAILPIT_API = 'http://localhost:8025/api/v1';
const REALM = 'otp-demo';
const TEST_USER = 'testuser';
const TEST_PASSWORD = 'password';

/**
 * Fetch the latest OTP code from Mailpit (email channel).
 * Polls until an email arrives or timeout.
 */
async function getEmailOtpCode(page, { timeoutMs = 15_000 } = {}) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const res = await page.request.get(`${MAILPIT_API}/messages?limit=1`);
    const body = await res.json();
    if (body.messages && body.messages.length > 0) {
      const msgId = body.messages[0].ID;
      const msgRes = await page.request.get(`${MAILPIT_API}/message/${msgId}`);
      const msg = await msgRes.json();
      const text = msg.Text || msg.HTML || '';
      const match = text.match(/\b(\d{6})\b/);
      if (match) {
        // Delete the message so it doesn't interfere with later tests
        await page.request.delete(`${MAILPIT_API}/messages`, {
          data: { IDs: [msgId] },
        });
        return match[1];
      }
    }
    await page.waitForTimeout(500);
  }
  throw new Error('Timed out waiting for OTP email');
}

const SMS_CODE_PATTERN = /Your verification code is:\s*(\d{6})/g;

function readKeycloakLogs(tail) {
  const { execSync } = require('child_process');
  const tailArg = tail ? ` --tail=${tail}` : '';
  return execSync(`docker compose logs keycloak${tailArg} 2>&1`, {
    cwd: require('path').resolve(__dirname, '../..'),
    encoding: 'utf-8',
  });
}

/**
 * Count how many SMS OTP codes the LogSmsSenderFactory has logged so far. Pass the result as
 * `afterCount` to getSmsOtpCodeFromLogs to wait for a code sent after that point.
 */
function countSmsSends() {
  return [...readKeycloakLogs().matchAll(SMS_CODE_PATTERN)].length;
}

/**
 * Fetch the latest SMS OTP code from Keycloak docker logs.
 * The LogSmsSenderFactory logs: "SMS to +...: Your verification code is: XXXXXX"
 *
 * Polls, because the OTP grant types deliver codes asynchronously (the code is logged shortly
 * after the phase-1 401). With `afterCount`, waits until more than that many codes have been
 * logged and returns the newest one, so a code left over from an earlier send is never used.
 */
async function getSmsOtpCodeFromLogs({ afterCount, timeoutMs = 15_000 } = {}) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const codes = afterCount === undefined
      ? [...readKeycloakLogs(20).matchAll(SMS_CODE_PATTERN)]
      : [...readKeycloakLogs().matchAll(SMS_CODE_PATTERN)];
    const fresh = afterCount === undefined ? codes.length > 0 : codes.length > afterCount;
    if (fresh) {
      return codes[codes.length - 1][1];
    }
    if (Date.now() >= deadline) {
      throw new Error('Could not find SMS OTP code in Keycloak logs');
    }
    await new Promise((r) => setTimeout(r, 250));
  }
}

/**
 * Delete all Mailpit messages (clean state).
 */
async function clearMailpit(page) {
  await page.request.delete(`${MAILPIT_API}/messages`, {
    data: { IDs: [] },
  });
}

/**
 * Navigate to account console login for the otp-demo realm.
 */
function accountConsoleUrl() {
  return `${KEYCLOAK_URL}/realms/${REALM}/account`;
}

module.exports = {
  KEYCLOAK_URL,
  MAILPIT_API,
  REALM,
  TEST_USER,
  TEST_PASSWORD,
  getEmailOtpCode,
  getSmsOtpCodeFromLogs,
  countSmsSends,
  clearMailpit,
  accountConsoleUrl,
};