package hr.delmisoft.keycloak.otp.grant;

import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.keycloak.OAuthErrorException;
import org.keycloak.authentication.AuthenticationProcessor;
import org.keycloak.common.util.Time;
import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventType;
import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.PasswordPolicy;
import org.keycloak.models.SingleUseObjectProvider;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.grants.OAuth2GrantTypeBase;
import org.keycloak.services.CorsErrorResponseException;
import org.keycloak.services.Urls;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.managers.AuthenticationSessionManager;
import org.keycloak.services.managers.BruteForceProtector;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;

import org.jboss.logging.Logger;

import hr.delmisoft.keycloak.otp.OtpHash;
import hr.delmisoft.keycloak.otp.OtpSendThrottle;

/**
 * Base class for OTP-based custom OAuth2 grant types.
 * Handles two-phase OTP flow: request OTP → verify OTP → issue tokens.
 * Password validation is optional — if the password parameter is present, it is validated.
 *
 * <h2>Account-enumeration resistance</h2>
 * The token endpoint is public, so no observable part of the response may depend on whether
 * the submitted username/email belongs to a usable account:
 * <ul>
 *   <li>Unknown, disabled, unverified-channel, brute-force-locked and required-actions accounts,
 *       and requests with a wrong {@code password}, all get the same phase-1 response as a
 *       successful send — including a syntactically valid but never-stored
 *       {@code otp_session_id}. No OTP is sent. Phase 2 with that id fails with the same
 *       generic "OTP session has expired" response a real-but-expired session gets.</li>
 *   <li>The phase-1 send throttle (HTTP 429) is keyed on the normalized identifier the client
 *       submitted, not on the resolved user, and is applied before the account is even looked
 *       up — so unknown usernames are throttled exactly like real ones, and a real account
 *       reached via a different identifier (email vs username) behaves like an unrelated
 *       identifier instead of revealing the link with a 429.</li>
 *   <li>The per-account send cooldown still caps real deliveries; when it blocks a send the
 *       caller gets the indistinguishable phase-1 response rather than a 429.</li>
 * </ul>
 *
 * <p><b>Residual timing difference:</b> every phase-1 request generates and hashes an OTP and,
 * when a password is supplied, pays for a password hash (a real verification or a dummy hash
 * with the realm's algorithm), so the CPU-bound work is comparable. What cannot be equalised
 * without delaying every response is the latency of actually delivering the OTP (SMTP / SMS
 * gateway) plus the extra cache writes for the real OTP session; a statistical timing attack
 * against a slow delivery channel can still distinguish "OTP was sent" from "not sent".
 * Deployments that need to close that gap should make delivery asynchronous in their
 * {@code SmsProvider} / mail setup.
 */
public abstract class AbstractOtpGrantType extends OAuth2GrantTypeBase {

    private static final Logger LOG = Logger.getLogger(AbstractOtpGrantType.class);
    private static final SecureRandom RANDOM = new SecureRandom();

    static final String NOTE_CODE_HASH = "codeHash";
    static final String NOTE_CODE_SALT = "codeSalt";
    static final String NOTE_USER_ID = "userId";
    static final String NOTE_CLIENT_ID = "clientId";
    static final String NOTE_ATTEMPTS = "attempts";

    static final int DEFAULT_CODE_LENGTH = 6;
    static final int DEFAULT_TTL = 300;
    static final int DEFAULT_MAX_RETRIES = 3;

    private static final String SESSION_EXPIRED_DESCRIPTION = "OTP session has expired";

    /** OTP code material prepared up front on every phase-1 request (see class docs, timing). */
    private record PreparedCode(String code, String salt, String hash, int expiresAt) {}

    @Override
    public Response process(Context context) {
        setContext(context);

        event.detail(Details.AUTH_METHOD, "otp");

        if (!client.isDirectAccessGrantsEnabled()) {
            event.error(Errors.NOT_ALLOWED);
            throw new CorsErrorResponseException(cors, OAuthErrorException.UNAUTHORIZED_CLIENT,
                    "Client not allowed for direct access grants", Response.Status.BAD_REQUEST);
        }

        if (client.isConsentRequired()) {
            event.error(Errors.CONSENT_DENIED);
            throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_CLIENT,
                    "Client requires user consent", Response.Status.BAD_REQUEST);
        }

        String scope = getRequestedScopes();
        String username = formParams.getFirst("username");

        if (username == null || username.isBlank()) {
            event.error(Errors.USERNAME_MISSING);
            throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_REQUEST,
                    "Missing parameter: username", Response.Status.BAD_REQUEST);
        }

        String otp = formParams.getFirst("otp");
        String otpSessionId = formParams.getFirst("otp_session_id");
        String password = formParams.getFirst("password");
        boolean isPhase2 = otp != null && !otp.isBlank();

        // Request-shape errors are reported before any account lookup so they cannot differ
        // between existing and non-existing usernames.
        if (isPhase2 && (otpSessionId == null || otpSessionId.isBlank())) {
            event.error(Errors.INVALID_USER_CREDENTIALS);
            throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_GRANT,
                    "Missing otp_session_id", Response.Status.UNAUTHORIZED);
        }

        PreparedCode prepared = null;
        int cooldown = 0;
        OtpSendThrottle.IpSlot ipSlot = null;
        if (!isPhase2) {
            // Generate + hash on every phase-1 request, real account or not, so the fake path
            // costs the same CPU work as the real one.
            prepared = prepareCode();
            cooldown = resolveCooldown();
            // Per-source-IP cap comes first so a blocked IP never consumes the identifier or
            // per-user cooldown. Taken before the account lookup, so real and unknown
            // usernames consume a slot alike and the limit is not an enumeration oracle.
            ipSlot = OtpSendThrottle.tryReserveIpSlot(session, realm, clientConnection);
            if (!ipSlot.isAllowed()) {
                return ipSendLimitedResponse(ipSlot);
            }
            // Throttle on the submitted identifier BEFORE looking the account up: every
            // identifier — existing or not — gets the same 429 on its second request.
            if (!OtpSendThrottle.tryReserveForIdentifier(session, realm, username, getChannel(), cooldown)) {
                OtpSendThrottle.releaseIpSlot(session, ipSlot);
                event.error(Errors.NOT_ALLOWED);
                return throttledResponse(username);
            }
        }

        UserModel user = lookupUser(username);
        String rejection = checkEligibility(user, password);
        if (rejection != null) {
            event.error(rejection);
            return isPhase2 ? indistinguishablePhase2Response(otpSessionId) : indistinguishablePhase1Response();
        }

        if (!isPhase2) {
            return handlePhase1(user, username, prepared, cooldown, ipSlot);
        } else {
            return handlePhase2(user, otp, otpSessionId, scope);
        }
    }

    /**
     * Returns {@code null} if the account may proceed with the OTP flow, or the event error
     * describing why not. All non-null outcomes are answered with the same indistinguishable
     * response, so the order of checks only affects event logging and the brute-force counter.
     */
    private String checkEligibility(UserModel user, String password) {
        boolean passwordSupplied = password != null && !password.isEmpty();
        String rejection = null;

        if (user == null) {
            rejection = Errors.USER_NOT_FOUND;
        } else if (!user.isEnabled()) {
            rejection = Errors.USER_DISABLED;
        } else {
            event.user(user);
            if (isBruteForceLocked(user)) {
                // Honor Keycloak's brute-force lockout, so the OTP grant cannot be used to
                // bypass the protections applied to the standard authentication flow.
                rejection = Errors.USER_TEMPORARILY_DISABLED;
            } else if (!isChannelVerified(user)) {
                // Channel verification gate. For email, default-on uses Keycloak's native
                // verified flag. For SMS it is off unless an admin opts in.
                rejection = Errors.INVALID_USER_CREDENTIALS;
            }
        }

        if (passwordSupplied) {
            if (rejection == null) {
                if (!user.credentialManager().isValid(UserCredentialModel.password(password))) {
                    recordBruteForceFailure(user);
                    rejection = Errors.INVALID_USER_CREDENTIALS;
                }
            } else {
                // Keep the password-hash cost on the rejection path so it is not a timing oracle.
                burnPasswordHash(password);
            }
        }

        // Refuse to proceed while the account still has required actions pending — matches
        // Keycloak's behavior for the standard direct-grant flow (no tokens are issued).
        if (rejection == null && user.getRequiredActionsStream().findAny().isPresent()) {
            rejection = Errors.RESOLVE_REQUIRED_ACTIONS;
        }
        return rejection;
    }

    private boolean isBruteForceLocked(UserModel user) {
        if (!realm.isBruteForceProtected()) {
            return false;
        }
        BruteForceProtector bfp = session.getProvider(BruteForceProtector.class);
        return bfp != null && bfp.isTemporarilyDisabled(session, realm, user);
    }

    /**
     * Hashes {@code password} with the realm's configured password-hash algorithm and discards
     * the result, approximating the cost of a real credential verification.
     */
    private void burnPasswordHash(String password) {
        try {
            PasswordPolicy policy = realm.getPasswordPolicy();
            String algorithm = policy != null ? policy.getHashAlgorithm() : null;
            PasswordHashProvider provider = algorithm != null
                    ? session.getProvider(PasswordHashProvider.class, algorithm) : null;
            if (provider == null) {
                provider = session.getProvider(PasswordHashProvider.class);
            }
            if (provider != null) {
                provider.encodedCredential(password, policy != null ? policy.getHashIterations() : -1);
            }
        } catch (RuntimeException e) {
            LOG.debug("Dummy password hash failed", e);
        }
    }

    private static PreparedCode prepareCode() {
        String code = generateCode(DEFAULT_CODE_LENGTH);
        String salt = OtpHash.newSalt();
        String hash = OtpHash.hash(code, salt);
        return new PreparedCode(code, salt, hash, (int) (Time.currentTime() + DEFAULT_TTL));
    }

    private Response otpRequiredResponse(String otpSessionId) {
        Map<String, Object> body = new HashMap<>();
        body.put("error", getOtpRequiredError());
        body.put("error_description", getOtpSentDescription());
        body.put("otp_session_id", otpSessionId);
        cors.add();
        return Response.status(Response.Status.UNAUTHORIZED)
                .entity(body)
                .type(MediaType.APPLICATION_JSON_TYPE)
                .build();
    }

    /**
     * Phase-1 response for requests that must not (or cannot) send an OTP. Identical to the
     * success response — including a syntactically valid {@code otp_session_id} — but no OTP
     * is sent and no session is created, so the id never resolves in phase 2.
     */
    private Response indistinguishablePhase1Response() {
        return otpRequiredResponse(UUID.randomUUID().toString());
    }

    /**
     * Generic phase-2 failure, identical to the real "OTP session has expired" outcome. The
     * submitted session id is consumed (if it exists) on every path that uses this response,
     * so the session's subsequent state cannot be used as a side channel either.
     */
    private Response indistinguishablePhase2Response(String otpSessionId) {
        if (otpSessionId != null && !otpSessionId.isBlank()) {
            session.getProvider(SingleUseObjectProvider.class).remove(otpSessionId);
        }
        Map<String, Object> body = new HashMap<>();
        body.put("error", getSessionExpiredError());
        body.put("error_description", SESSION_EXPIRED_DESCRIPTION);
        cors.add();
        return Response.status(Response.Status.UNAUTHORIZED)
                .entity(body)
                .type(MediaType.APPLICATION_JSON_TYPE)
                .build();
    }

    private Response throttledResponse(String username) {
        int retryAfter = Math.max(1,
                OtpSendThrottle.remainingSecondsForIdentifier(session, realm, username, getChannel()));
        Map<String, Object> body = new HashMap<>();
        body.put("error", "otp_send_throttled");
        body.put("error_description", "Too many OTP send requests. Retry in " + retryAfter + " seconds.");
        body.put("retry_after", retryAfter);
        cors.add();
        return Response.status(429)
                .header("Retry-After", String.valueOf(retryAfter))
                .entity(body)
                .type(MediaType.APPLICATION_JSON_TYPE)
                .build();
    }

    /**
     * 429 for a request blocked by the per-source-IP send limit ({@code otp.ipSendLimit} per
     * {@code otp.ipSendWindow}). Same shape as the identifier cooldown response.
     */
    private Response ipSendLimitedResponse(OtpSendThrottle.IpSlot ipSlot) {
        int retryAfter = ipSlot.retryAfterSeconds();
        event.detail(Details.REASON, "otp_ip_send_limit");
        event.error(Errors.NOT_ALLOWED);
        Map<String, Object> body = new HashMap<>();
        body.put("error", "otp_send_throttled");
        body.put("error_description", "Too many OTP send requests. Retry in " + retryAfter + " seconds.");
        body.put("retry_after", retryAfter);
        cors.add();
        return Response.status(429)
                .header("Retry-After", String.valueOf(retryAfter))
                .entity(body)
                .type(MediaType.APPLICATION_JSON_TYPE)
                .build();
    }

    private void recordBruteForceFailure(UserModel user) {
        if (!realm.isBruteForceProtected()) {
            return;
        }
        BruteForceProtector bfp = session.getProvider(BruteForceProtector.class);
        if (bfp != null) {
            bfp.failedLogin(realm, user, clientConnection, session.getContext().getUri(), Set.of(client.getClientId()));
        }
    }

    /**
     * Phase 1: Send the prepared OTP, return 401 with session ID. The per-identifier throttle
     * has already been reserved by {@link #process}.
     */
    private Response handlePhase1(UserModel user, String username, PreparedCode prepared, int cooldown,
                                  OtpSendThrottle.IpSlot ipSlot) {
        if (!OtpSendThrottle.tryReserveWithCodeHash(session, realm, user, getChannel(), cooldown,
                prepared.hash(), prepared.salt(), prepared.expiresAt())) {
            // The account-level cooldown is still running from a request made under a different
            // identifier (email vs username) or from the browser flow. A 429 here would link
            // that identifier to this account, so answer like any other identifier — without
            // sending a second OTP. The previously delivered code remains valid.
            event.error(Errors.NOT_ALLOWED);
            return indistinguishablePhase1Response();
        }

        String sessionId = UUID.randomUUID().toString();

        Map<String, String> notes = new HashMap<>();
        notes.put(NOTE_CODE_HASH, prepared.hash());
        notes.put(NOTE_CODE_SALT, prepared.salt());
        notes.put(NOTE_USER_ID, user.getId());
        notes.put(NOTE_CLIENT_ID, client.getClientId());
        notes.put(NOTE_ATTEMPTS, "0");

        SingleUseObjectProvider store = session.getProvider(SingleUseObjectProvider.class);
        store.put(sessionId, DEFAULT_TTL, notes);

        try {
            sendOtp(user, prepared.code());
        } catch (Exception e) {
            LOG.error("Failed to send OTP", e);
            // Roll back so a transient delivery error doesn't lock the user out of retries
            // by leaving a cooldown protecting an OTP that was never received.
            store.remove(sessionId);
            OtpSendThrottle.release(session, realm, user, getChannel());
            OtpSendThrottle.releaseIdentifier(session, realm, username, getChannel());
            OtpSendThrottle.releaseIpSlot(session, ipSlot);
            event.error(Errors.EMAIL_SEND_FAILED);
            throw new CorsErrorResponseException(cors, "otp_send_failed",
                    "Failed to send OTP", Response.Status.INTERNAL_SERVER_ERROR);
        }

        return otpRequiredResponse(sessionId);
    }

    /**
     * Resolves the send cooldown (seconds) from the realm attribute {@code otp.sendCooldown},
     * falling back to {@link OtpSendThrottle#DEFAULT_SEND_COOLDOWN}. Accepts {@code 0} to
     * disable throttling, matching the documented behavior.
     */
    private int resolveCooldown() {
        String configured = realm.getAttribute(OtpSendThrottle.CONFIG_SEND_COOLDOWN);
        if (configured == null || configured.isBlank()) {
            return OtpSendThrottle.DEFAULT_SEND_COOLDOWN;
        }
        try {
            int parsed = Integer.parseInt(configured);
            return parsed >= 0 ? parsed : OtpSendThrottle.DEFAULT_SEND_COOLDOWN;
        } catch (NumberFormatException e) {
            return OtpSendThrottle.DEFAULT_SEND_COOLDOWN;
        }
    }

    /**
     * Phase 2: Validate OTP and generate token response.
     */
    private Response handlePhase2(UserModel user, String otp, String otpSessionId, String scope) {
        SingleUseObjectProvider store = session.getProvider(SingleUseObjectProvider.class);
        Map<String, String> rawNotes = store.get(otpSessionId);

        if (rawNotes == null) {
            event.error(Errors.INVALID_USER_CREDENTIALS);
            return indistinguishablePhase2Response(otpSessionId);
        }

        Map<String, String> notes = new HashMap<>(rawNotes);

        // Verify user binding. Answered (and the session consumed) exactly like a fake session
        // id, so a session obtained for one account cannot probe whether other usernames exist.
        String storedUserId = notes.get(NOTE_USER_ID);
        if (storedUserId == null || !user.getId().equals(storedUserId)) {
            event.error(Errors.INVALID_USER_CREDENTIALS);
            return indistinguishablePhase2Response(otpSessionId);
        }

        // Verify client binding — refuse to redeem an OTP session against a different client
        // than the one that initiated phase 1.
        String storedClientId = notes.get(NOTE_CLIENT_ID);
        if (storedClientId == null || !storedClientId.equals(client.getClientId())) {
            store.remove(otpSessionId);
            event.error(Errors.INVALID_CLIENT_CREDENTIALS);
            throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_GRANT,
                    "Invalid OTP session", Response.Status.UNAUTHORIZED);
        }

        // Check max retries (treat malformed counter as session-corrupt and fail closed).
        int attempts;
        try {
            attempts = Integer.parseInt(notes.get(NOTE_ATTEMPTS));
        } catch (NumberFormatException e) {
            store.remove(otpSessionId);
            event.error(Errors.INVALID_USER_CREDENTIALS);
            throw new CorsErrorResponseException(cors, getSessionExpiredError(),
                    "OTP session is corrupt", Response.Status.UNAUTHORIZED);
        }
        if (attempts >= DEFAULT_MAX_RETRIES) {
            store.remove(otpSessionId);
            event.error(Errors.INVALID_USER_CREDENTIALS);
            throw new CorsErrorResponseException(cors, getMaxRetriesError(),
                    "Too many failed attempts", Response.Status.UNAUTHORIZED);
        }

        // Validate code (hashed)
        String storedHash = notes.get(NOTE_CODE_HASH);
        String storedSalt = notes.get(NOTE_CODE_SALT);
        if (storedHash == null || storedSalt == null) {
            store.remove(otpSessionId);
            event.error(Errors.INVALID_USER_CREDENTIALS);
            throw new CorsErrorResponseException(cors, getSessionExpiredError(),
                    "OTP session is corrupt", Response.Status.UNAUTHORIZED);
        }

        if (!OtpHash.verify(otp, storedHash, storedSalt)) {
            notes.put(NOTE_ATTEMPTS, String.valueOf(attempts + 1));
            store.replace(otpSessionId, notes);
            recordBruteForceFailure(user);
            event.error(Errors.INVALID_USER_CREDENTIALS);
            throw new CorsErrorResponseException(cors, getOtpInvalidError(),
                    "Invalid OTP code", Response.Status.UNAUTHORIZED);
        }

        // OTP valid — consume session and generate tokens
        store.remove(otpSessionId);
        return generateTokenResponse(user, scope);
    }

    /**
     * Creates a user session and generates the token response.
     */
    private Response generateTokenResponse(UserModel user, String scope) {
        RootAuthenticationSessionModel rootAuthSession =
                new AuthenticationSessionManager(session).createAuthenticationSession(realm, false);
        AuthenticationSessionModel authSession = rootAuthSession.createAuthenticationSession(client);

        authSession.setProtocol(OIDCLoginProtocol.LOGIN_PROTOCOL);
        authSession.setAction(AuthenticatedClientSessionModel.Action.AUTHENTICATE.name());
        authSession.setClientNote(OIDCLoginProtocol.ISSUER,
                Urls.realmIssuer(session.getContext().getUri().getBaseUri(), realm.getName()));
        authSession.setClientNote(OIDCLoginProtocol.SCOPE_PARAM, scope);
        authSession.setAuthenticatedUser(user);

        AuthenticationManager.setClientScopesInSession(session, authSession);

        AuthenticationProcessor processor = new AuthenticationProcessor();
        processor.setAuthenticationSession(authSession)
                .setConnection(clientConnection)
                .setEventBuilder(event)
                .setRealm(realm)
                .setSession(session)
                .setUriInfo(session.getContext().getUri())
                .setRequest(request);

        ClientSessionContext clientSessionCtx = processor.attachSession();
        UserSessionModel userSession = processor.getUserSession();
        updateUserSessionFromClientAuth(userSession);

        return createTokenResponse(user, userSession, clientSessionCtx, scope, false, null);
    }

    private UserModel lookupUser(String username) {
        UserModel user = session.users().getUserByUsername(realm, username);
        if (user == null && realm.isLoginWithEmailAllowed()) {
            user = session.users().getUserByEmail(realm, username);
        }
        return user;
    }

    static String generateCode(int length) {
        int bound = (int) Math.pow(10, length);
        int code = RANDOM.nextInt(bound);
        return String.format("%0" + length + "d", code);
    }

    @Override
    public EventType getEventType() {
        return EventType.LOGIN;
    }

    /** OTP grants only take short scalar parameters, no long "token" parameters. */
    @Override
    public Set<String> getTokenParameterNames() {
        return Set.of();
    }

    // Template methods for subclasses

    /** Send the OTP code to the user (email or SMS). */
    protected abstract void sendOtp(UserModel user, String code) throws Exception;

    /** Error code returned in phase 1 response (e.g. "email_otp_required"). */
    protected abstract String getOtpRequiredError();

    /** Human-readable description returned in phase 1 response. */
    protected abstract String getOtpSentDescription();

    /** Error code for expired OTP session. */
    protected abstract String getSessionExpiredError();

    /** Error code for invalid OTP code. */
    protected abstract String getOtpInvalidError();

    /** Error code for max retries exceeded. */
    protected abstract String getMaxRetriesError();

    /** Throttle channel name (e.g. {@code "email"} or {@code "sms"}). */
    protected abstract String getChannel();

    /**
     * Verifies that the user's destination channel is trusted enough to use as an
     * authentication factor (e.g. {@code emailVerified} for email; a configurable verified-
     * phone attribute for SMS). Returning {@code false} causes the grant to respond as if
     * the account did not exist.
     */
    protected abstract boolean isChannelVerified(UserModel user);
}
