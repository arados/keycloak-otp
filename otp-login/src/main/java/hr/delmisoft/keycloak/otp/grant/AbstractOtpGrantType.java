package hr.delmisoft.keycloak.otp.grant;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.keycloak.OAuthErrorException;
import org.keycloak.authentication.AuthenticationProcessor;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventType;
import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.ClientSessionContext;
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
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;

import org.jboss.logging.Logger;

/**
 * Base class for OTP-based custom OAuth2 grant types.
 * Handles two-phase OTP flow: request OTP → verify OTP → issue tokens.
 * Password validation is optional — if the password parameter is present, it is validated.
 */
public abstract class AbstractOtpGrantType extends OAuth2GrantTypeBase {

    private static final Logger LOG = Logger.getLogger(AbstractOtpGrantType.class);
    private static final SecureRandom RANDOM = new SecureRandom();

    static final String NOTE_CODE = "code";
    static final String NOTE_USER_ID = "userId";
    static final String NOTE_ATTEMPTS = "attempts";

    static final int DEFAULT_CODE_LENGTH = 6;
    static final int DEFAULT_TTL = 300;
    static final int DEFAULT_MAX_RETRIES = 3;

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

        UserModel user = lookupUser(username);
        if (user == null) {
            event.error(Errors.USER_NOT_FOUND);
            throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_GRANT,
                    "Invalid user credentials", Response.Status.UNAUTHORIZED);
        }

        if (!user.isEnabled()) {
            event.error(Errors.USER_DISABLED);
            throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_GRANT,
                    "Account disabled", Response.Status.BAD_REQUEST);
        }

        event.user(user);

        // Validate password if provided
        String password = formParams.getFirst("password");
        if (password != null && !password.isEmpty()) {
            if (!user.credentialManager().isValid(UserCredentialModel.password(password))) {
                event.error(Errors.INVALID_USER_CREDENTIALS);
                throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_GRANT,
                        "Invalid user credentials", Response.Status.UNAUTHORIZED);
            }
        }

        // Check if this is phase 2 (OTP submission)
        String otp = formParams.getFirst("otp");
        String otpSessionId = formParams.getFirst("otp_session_id");

        if (otp == null || otp.isBlank()) {
            return handlePhase1(user);
        } else {
            return handlePhase2(user, otp, otpSessionId, scope);
        }
    }

    /**
     * Phase 1: Generate and send OTP, return 401 with session ID.
     */
    private Response handlePhase1(UserModel user) {
        String code = generateCode(DEFAULT_CODE_LENGTH);
        String sessionId = UUID.randomUUID().toString();

        Map<String, String> notes = new HashMap<>();
        notes.put(NOTE_CODE, code);
        notes.put(NOTE_USER_ID, user.getId());
        notes.put(NOTE_ATTEMPTS, "0");

        SingleUseObjectProvider store = session.getProvider(SingleUseObjectProvider.class);
        store.put(sessionId, DEFAULT_TTL, notes);

        try {
            sendOtp(user, code);
        } catch (Exception e) {
            LOG.error("Failed to send OTP", e);
            store.remove(sessionId);
            event.error(Errors.EMAIL_SEND_FAILED);
            throw new CorsErrorResponseException(cors, "otp_send_failed",
                    "Failed to send OTP", Response.Status.INTERNAL_SERVER_ERROR);
        }

        Map<String, Object> body = new HashMap<>();
        body.put("error", getOtpRequiredError());
        body.put("error_description", getOtpSentDescription());
        body.put("otp_session_id", sessionId);

        cors.add();
        return Response.status(Response.Status.UNAUTHORIZED)
                .entity(body)
                .type(MediaType.APPLICATION_JSON_TYPE)
                .build();
    }

    /**
     * Phase 2: Validate OTP and generate token response.
     */
    private Response handlePhase2(UserModel user, String otp, String otpSessionId, String scope) {
        if (otpSessionId == null || otpSessionId.isBlank()) {
            event.error(Errors.INVALID_USER_CREDENTIALS);
            throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_GRANT,
                    "Missing otp_session_id", Response.Status.UNAUTHORIZED);
        }

        SingleUseObjectProvider store = session.getProvider(SingleUseObjectProvider.class);
        Map<String, String> rawNotes = store.get(otpSessionId);

        if (rawNotes == null) {
            event.error(Errors.INVALID_USER_CREDENTIALS);
            throw new CorsErrorResponseException(cors, getSessionExpiredError(),
                    "OTP session has expired", Response.Status.UNAUTHORIZED);
        }

        Map<String, String> notes = new HashMap<>(rawNotes);

        // Verify user binding
        String storedUserId = notes.get(NOTE_USER_ID);
        if (storedUserId == null || !user.getId().equals(storedUserId)) {
            store.remove(otpSessionId);
            event.error(Errors.INVALID_USER_CREDENTIALS);
            throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_GRANT,
                    "Invalid OTP session", Response.Status.UNAUTHORIZED);
        }

        // Check max retries
        int attempts = Integer.parseInt(notes.get(NOTE_ATTEMPTS));
        if (attempts >= DEFAULT_MAX_RETRIES) {
            store.remove(otpSessionId);
            event.error(Errors.INVALID_USER_CREDENTIALS);
            throw new CorsErrorResponseException(cors, getMaxRetriesError(),
                    "Too many failed attempts", Response.Status.UNAUTHORIZED);
        }

        // Validate code
        String storedCode = notes.get(NOTE_CODE);
        if (storedCode == null) {
            store.remove(otpSessionId);
            event.error(Errors.INVALID_USER_CREDENTIALS);
            throw new CorsErrorResponseException(cors, getSessionExpiredError(),
                    "OTP session is corrupt", Response.Status.UNAUTHORIZED);
        }

        if (!MessageDigest.isEqual(storedCode.getBytes(java.nio.charset.StandardCharsets.UTF_8), otp.getBytes(java.nio.charset.StandardCharsets.UTF_8))) {
            notes.put(NOTE_ATTEMPTS, String.valueOf(attempts + 1));
            store.replace(otpSessionId, notes);
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
}
