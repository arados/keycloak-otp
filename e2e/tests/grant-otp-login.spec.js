const { test, expect } = require('@playwright/test');
const {
  TEST_USER,
  KEYCLOAK_URL,
  REALM,
  countSmsSends,
  getSmsOtpCodeFromLogs,
} = require('./helpers');

/**
 * End-to-end OTP grant (urn:otp:sms) login.
 *
 * Phase 1 answers before the OTP is delivered (delivery runs asynchronously so response time
 * does not reveal whether a code was sent); the code shows up in the logs shortly after.
 * Phase 2 attempts are limited atomically per delivered code (3 guesses), even when many
 * guesses race against one otp_session_id.
 *
 * Demo realm sets otp.sendCooldown=5s; every test starts past that cooldown.
 */
test.describe('OTP grant type login (SMS, cooldown=5s, maxRetries=3)', () => {
  test.describe.configure({ mode: 'serial' });

  const TOKEN_URL = `${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/token`;
  const CLIENT_ID = 'passwordless-demo-client';
  const wait = (ms) => new Promise((r) => setTimeout(r, ms));

  async function token(request, extra) {
    const res = await request.post(TOKEN_URL, {
      form: { grant_type: 'urn:otp:sms', client_id: CLIENT_ID, username: TEST_USER, ...extra },
    });
    return { status: res.status(), body: await res.json() };
  }

  function wrongCodeFor(code) {
    const last = code[code.length - 1];
    return code.slice(0, -1) + (last === '9' ? '0' : String(Number(last) + 1));
  }

  async function requestCode(request) {
    const before = countSmsSends();
    const phase1 = await token(request, {});
    expect(phase1.status).toBe(401);
    expect(phase1.body.error).toBe('sms_otp_required');
    expect(phase1.body.otp_session_id).toBeTruthy();
    const code = await getSmsOtpCodeFromLogs({ afterCount: before });
    return { sessionId: phase1.body.otp_session_id, code };
  }

  test.beforeAll(async () => {
    await wait(6_000);
  });

  test.afterAll(async () => {
    await wait(6_000);
  });

  test('asynchronously delivered code redeems for tokens exactly once', async ({ request }) => {
    const { sessionId, code } = await requestCode(request);

    const ok = await token(request, { otp: code, otp_session_id: sessionId });
    expect(ok.status).toBe(200);
    expect(ok.body.access_token).toBeTruthy();

    const replay = await token(request, { otp: code, otp_session_id: sessionId });
    expect(replay.status).toBe(401);
    expect(replay.body.error).toBe('smsOtpSessionExpired');
  });

  test('concurrent wrong guesses cannot exceed the attempt limit', async ({ request }) => {
    await wait(6_000);
    const { sessionId, code } = await requestCode(request);
    const wrong = wrongCodeFor(code);

    const results = await Promise.all(
      Array.from({ length: 20 }, () => token(request, { otp: wrong, otp_session_id: sessionId }))
    );
    const errors = results.map((r) => r.body.error);
    for (const r of results) {
      expect(r.status).toBe(401);
    }
    expect(errors.filter((e) => e === 'smsOtpInvalid')).toHaveLength(3);
    for (const e of errors) {
      expect(['smsOtpInvalid', 'smsOtpMaxRetries', 'smsOtpSessionExpired']).toContain(e);
    }

    // The code is burned: even the correct code no longer works.
    const late = await token(request, { otp: code, otp_session_id: sessionId });
    expect(late.status).toBe(401);
    expect(['smsOtpMaxRetries', 'smsOtpSessionExpired']).toContain(late.body.error);
  });
});
