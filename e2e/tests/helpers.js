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

/**
 * Fetch the latest SMS OTP code from Keycloak docker logs.
 * The LogSmsSenderFactory logs: "SMS to +...: Your verification code is: XXXXXX"
 */
async function getSmsOtpCodeFromLogs() {
  const { execSync } = require('child_process');
  const logs = execSync('docker compose logs keycloak --tail=20 2>&1', {
    cwd: require('path').resolve(__dirname, '../..'),
    encoding: 'utf-8',
  });
  const lines = logs.split('\n').reverse();
  for (const line of lines) {
    const match = line.match(/Your verification code is:\s*(\d{6})/);
    if (match) return match[1];
  }
  throw new Error('Could not find SMS OTP code in Keycloak logs');
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
  clearMailpit,
  accountConsoleUrl,
};