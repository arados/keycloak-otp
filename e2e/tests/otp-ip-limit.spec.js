const { test, expect } = require('@playwright/test');
const { KEYCLOAK_URL, REALM } = require('./helpers');

/**
 * Per-source-IP OTP send limit (realm attributes otp.ipSendLimit / otp.ipSendWindow).
 *
 * The demo realm ships with a high limit so the rest of the suite (which sends every OTP from
 * one IP) is never blocked. This spec temporarily lowers the limit through the admin API,
 * checks that the grant type answers 429, and restores the original realm attributes.
 */
test.describe('Per-IP OTP send limit (grant type)', () => {
  test.describe.configure({ mode: 'serial' });

  const TOKEN_URL = `${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/token`;
  const REALM_ADMIN_URL = `${KEYCLOAK_URL}/admin/realms/${REALM}`;

  async function adminToken(request) {
    const res = await request.post(`${KEYCLOAK_URL}/realms/master/protocol/openid-connect/token`, {
      form: { grant_type: 'password', client_id: 'admin-cli', username: 'admin', password: 'admin' },
    });
    expect(res.status()).toBe(200);
    return (await res.json()).access_token;
  }

  async function setRealmAttributes(request, token, rep, attributes) {
    const res = await request.put(REALM_ADMIN_URL, {
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      data: { ...rep, attributes },
    });
    expect(res.status()).toBe(204);
  }

  test('phase-1 requests beyond the IP limit return HTTP 429 with Retry-After', async ({ request }) => {
    const token = await adminToken(request);
    const repRes = await request.get(REALM_ADMIN_URL, { headers: { Authorization: `Bearer ${token}` } });
    expect(repRes.status()).toBe(200);
    const rep = await repRes.json();
    const originalAttributes = { ...(rep.attributes || {}) };

    await setRealmAttributes(request, token, rep, {
      ...originalAttributes,
      'otp.ipSendLimit': '2',
      'otp.ipSendWindow': '30',
    });

    try {
      // Unknown usernames consume an IP slot exactly like real sends (so the limit is not an
      // account-enumeration oracle), and they don't touch any real user's cooldown.
      const statuses = [];
      let last;
      for (let i = 0; i < 3; i++) {
        last = await request.post(TOKEN_URL, {
          form: {
            grant_type: 'urn:otp:sms',
            client_id: 'passwordless-demo-client',
            username: `ip-limit-ghost-${Date.now()}-${i}`,
          },
        });
        statuses.push(last.status());
      }

      // Earlier specs may already hold slots in the current window, so the first two requests
      // can be either accepted (401 + otp_session_id) or throttled; the third must be throttled.
      for (const s of statuses) {
        expect([401, 429]).toContain(s);
      }
      expect(statuses[2]).toBe(429);

      const body = await last.json();
      expect(body.error).toBe('otp_send_throttled');
      expect(body.retry_after).toBeGreaterThan(0);
      expect(body.retry_after).toBeLessThanOrEqual(30);
      expect(parseInt(last.headers()['retry-after'], 10)).toBeGreaterThan(0);
    } finally {
      await setRealmAttributes(request, token, rep, originalAttributes);
    }
  });
});
