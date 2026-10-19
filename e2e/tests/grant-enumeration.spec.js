const { test, expect } = require('@playwright/test');
const { TEST_USER, KEYCLOAK_URL, REALM } = require('./helpers');

/**
 * Account-enumeration parity for the OTP grant types: a real account and a username that
 * does not exist must produce the same sequence of token-endpoint responses.
 *
 * Demo realm sets otp.sendCooldown=5s, so the throttle tests are fast; afterAll waits past
 * the cooldown so later specs that use TEST_USER are not affected.
 */
test.describe('OTP grant types do not reveal account existence (SMS, cooldown=5s)', () => {
  test.describe.configure({ mode: 'serial' });

  const TOKEN_URL = `${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/token`;
  const CLIENT_ID = 'passwordless-demo-client';

  function unknownUsername() {
    return `no-such-user-${Date.now()}-${Math.floor(Math.random() * 1e9)}`;
  }

  async function phase1(request, username, extra = {}) {
    const params = new URLSearchParams({
      grant_type: 'urn:otp:sms',
      client_id: CLIENT_ID,
      username,
      ...extra,
    });
    const res = await request.post(TOKEN_URL, {
      data: params.toString(),
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    });
    const body = await res.json();
    return {
      status: res.status(),
      error: body.error,
      keys: Object.keys(body).sort(),
      retryAfter: res.headers()['retry-after'],
      body,
    };
  }

  function expectSameShape(real, unknown) {
    expect(real.status).toBe(unknown.status);
    expect(real.error).toBe(unknown.error);
    expect(real.keys).toEqual(unknown.keys);
    expect(Boolean(real.retryAfter)).toBe(Boolean(unknown.retryAfter));
  }

  test.beforeAll(async () => {
    // Don't collide with a cooldown left over by earlier specs.
    await new Promise((r) => setTimeout(r, 6_000));
  });

  test.afterAll(async () => {
    await new Promise((r) => setTimeout(r, 6_000));
  });

  test('unknown username is throttled with 429 exactly like a real account', async ({ request }) => {
    const ghost = unknownUsername();

    const real1 = await phase1(request, TEST_USER);
    const real2 = await phase1(request, TEST_USER);
    const unknown1 = await phase1(request, ghost);
    const unknown2 = await phase1(request, ghost);

    expect(real1.status).toBe(401);
    expect(real1.body.otp_session_id).toBeTruthy();
    expectSameShape(real1, unknown1);

    expect(real2.status).toBe(429);
    expect(real2.error).toBe('otp_send_throttled');
    expectSameShape(real2, unknown2);
    expect(unknown2.body.retry_after).toBeGreaterThan(0);
    expect(unknown2.body.retry_after).toBeLessThanOrEqual(5);
  });

  test('wrong password is indistinguishable from an unknown username', async ({ request }) => {
    await new Promise((r) => setTimeout(r, 6_000));
    const ghost = unknownUsername();

    const real1 = await phase1(request, TEST_USER, { password: 'definitely-wrong' });
    const unknown1 = await phase1(request, ghost, { password: 'definitely-wrong' });
    expect(real1.status).toBe(401);
    expect(real1.error).toBe('sms_otp_required');
    expectSameShape(real1, unknown1);

    // The wrong-password attempt still consumes the send slot, just like the unknown one.
    const real2 = await phase1(request, TEST_USER, { password: 'definitely-wrong' });
    const unknown2 = await phase1(request, ghost, { password: 'definitely-wrong' });
    expect(real2.status).toBe(429);
    expectSameShape(real2, unknown2);

    // Phase 2 against the returned session ids fails identically.
    const realPhase2 = await phase1(request, TEST_USER, {
      password: 'definitely-wrong',
      otp: '123456',
      otp_session_id: real1.body.otp_session_id,
    });
    const unknownPhase2 = await phase1(request, ghost, {
      password: 'definitely-wrong',
      otp: '123456',
      otp_session_id: unknown1.body.otp_session_id,
    });
    expect(realPhase2.status).toBe(401);
    expectSameShape(realPhase2, unknownPhase2);
    expect(realPhase2.body.error_description).toBe(unknownPhase2.body.error_description);
  });
});
