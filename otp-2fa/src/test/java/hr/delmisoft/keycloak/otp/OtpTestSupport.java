package hr.delmisoft.keycloak.otp;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.common.util.Time;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.SingleUseObjectProvider;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.mockito.ArgumentCaptor;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.atLeast;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockingDetails;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Shared helpers for multi-step authenticator tests that need real state across
 * requests: an in-memory {@link SingleUseObjectProvider} (shared by every "auth session",
 * like the Infinispan-backed store in a real deployment) and auth sessions whose notes
 * are backed by a plain map.
 */
public final class OtpTestSupport {

    /** Outcome marker for {@link #outcome} when {@code context.success()} was called. */
    public static final String SUCCESS = "SUCCESS";
    /** Outcome marker for {@link #outcome} when a form was rendered without an error. */
    public static final String FORM_WITHOUT_ERROR = "FORM_WITHOUT_ERROR";

    private OtpTestSupport() {}

    /** Auth session mock whose auth notes are stored in {@code notes}. */
    public static AuthenticationSessionModel statefulAuthSession(Map<String, String> notes) {
        AuthenticationSessionModel s = mock(AuthenticationSessionModel.class);
        when(s.getAuthNote(anyString())).thenAnswer(inv -> notes.get(inv.<String>getArgument(0)));
        doAnswer(inv -> {
            notes.put(inv.getArgument(0), inv.getArgument(1));
            return null;
        }).when(s).setAuthNote(anyString(), anyString());
        doAnswer(inv -> {
            notes.remove(inv.<String>getArgument(0));
            return null;
        }).when(s).removeAuthNote(anyString());
        return s;
    }

    /**
     * Returns {@link #SUCCESS} if {@code context.success()} was invoked since the last
     * {@code clearInvocations}, otherwise the last error key set on {@code form}, or
     * {@link #FORM_WITHOUT_ERROR}.
     */
    public static String outcome(AuthenticationFlowContext context, LoginFormsProvider form) {
        boolean succeeded = mockingDetails(context).getInvocations().stream()
                .anyMatch(i -> i.getMethod().getName().equals("success"));
        if (succeeded) {
            return SUCCESS;
        }
        ArgumentCaptor<String> err = ArgumentCaptor.forClass(String.class);
        verify(form, atLeast(0)).setError(err.capture());
        List<String> errors = err.getAllValues();
        return errors.isEmpty() ? FORM_WITHOUT_ERROR : errors.get(errors.size() - 1);
    }

    /** A different code of the same length. */
    public static String wrongCodeFor(String code) {
        char last = code.charAt(code.length() - 1);
        char flipped = last == '9' ? '0' : (char) (last + 1);
        return code.substring(0, code.length() - 1) + flipped;
    }

    /**
     * Minimal in-memory {@link SingleUseObjectProvider} with lifespans honoring
     * {@link Time#currentTime()} (so tests can fast-forward with {@link Time#setOffset}).
     */
    public static final class InMemorySingleUseObjectProvider implements SingleUseObjectProvider {

        private static final class Entry {
            final Map<String, String> notes;
            final long expiresAt;

            Entry(Map<String, String> notes, long expiresAt) {
                this.notes = notes;
                this.expiresAt = expiresAt;
            }
        }

        private final Map<String, Entry> entries = new HashMap<>();

        private Entry live(String key) {
            Entry e = entries.get(key);
            if (e != null && Time.currentTime() >= e.expiresAt) {
                entries.remove(key);
                return null;
            }
            return e;
        }

        @Override
        public synchronized void put(String key, long lifespanSeconds, Map<String, String> notes) {
            entries.put(key, new Entry(new HashMap<>(notes), Time.currentTime() + lifespanSeconds));
        }

        @Override
        public synchronized Map<String, String> get(String key) {
            Entry e = live(key);
            return e == null ? null : new HashMap<>(e.notes);
        }

        @Override
        public synchronized Map<String, String> remove(String key) {
            Entry e = live(key);
            entries.remove(key);
            return e == null ? null : e.notes;
        }

        @Override
        public synchronized boolean replace(String key, Map<String, String> notes) {
            Entry e = live(key);
            if (e == null) {
                return false;
            }
            entries.put(key, new Entry(new HashMap<>(notes), e.expiresAt));
            return true;
        }

        @Override
        public synchronized boolean putIfAbsent(String key, long lifespanInSeconds) {
            if (live(key) != null) {
                return false;
            }
            entries.put(key, new Entry(new HashMap<>(), Time.currentTime() + lifespanInSeconds));
            return true;
        }

        @Override
        public synchronized boolean contains(String key) {
            return live(key) != null;
        }

        @Override
        public void close() {
            // no-op
        }
    }
}
