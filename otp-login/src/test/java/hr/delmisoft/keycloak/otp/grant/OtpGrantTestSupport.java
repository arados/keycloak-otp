package hr.delmisoft.keycloak.otp.grant;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.AbstractExecutorService;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;

import org.keycloak.common.ClientConnection;
import org.keycloak.events.EventBuilder;
import org.keycloak.executors.ExecutorsProvider;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.KeycloakTransaction;
import org.keycloak.models.KeycloakTransactionManager;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RealmProvider;
import org.keycloak.models.SingleUseObjectProvider;
import org.keycloak.protocol.oidc.grants.OAuth2GrantType;
import org.keycloak.protocol.oidc.grants.OAuth2GrantTypeBase;
import org.keycloak.services.cors.Cors;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Shared scaffolding for grant-type unit tests.
 * <p>
 * The {@link OAuth2GrantTypeBase#setContext} machinery wants a populated
 * {@link OAuth2GrantType.Context} with package-private fields. Reflecting against that on every
 * test would be noisy, so the grant under test is given a no-op {@code setContext} override and
 * its protected fields are assigned directly via reflection. This keeps each test's setup focused
 * on the dependencies the assertions actually care about.
 */
final class OtpGrantTestSupport {

    private OtpGrantTestSupport() {}

    static void injectMocks(OAuth2GrantTypeBase grant,
                            KeycloakSession session,
                            RealmModel realm,
                            ClientModel client,
                            ClientConnection clientConnection,
                            MultivaluedMap<String, String> formParams,
                            EventBuilder event,
                            Cors cors,
                            HttpRequest request) {
        setField(grant, "session", session);
        setField(grant, "realm", realm);
        setField(grant, "client", client);
        setField(grant, "clientConnection", clientConnection);
        setField(grant, "formParams", formParams);
        setField(grant, "event", event);
        setField(grant, "cors", cors);
        setField(grant, "request", request);
        setField(grant, "clientAuthAttributes", new HashMap<String, String>());
    }

    /**
     * Build a minimal Context so {@link OAuth2GrantTypeBase#setContext} has something non-null
     * to swallow when {@code process()} is invoked. Test subclasses override {@code setContext}
     * to a no-op, so the context's contents do not actually flow into the grant; this method
     * just satisfies the method signature. Note: the Context constructor calls
     * {@code session.getContext()}, so a non-null session mock is required.
     */
    static OAuth2GrantType.Context dummyContext(KeycloakSession session) {
        return new OAuth2GrantType.Context(session, null,
                new HashMap<>(),
                new MultivaluedHashMap<>(),
                null, null, null);
    }

    private static void setField(Object target, String name, Object value) {
        Class<?> cls = target.getClass();
        while (cls != null) {
            try {
                Field f = cls.getDeclaredField(name);
                f.setAccessible(true);
                f.set(target, value);
                return;
            } catch (NoSuchFieldException e) {
                cls = cls.getSuperclass();
            } catch (IllegalAccessException e) {
                throw new RuntimeException("Failed to set field " + name, e);
            }
        }
        throw new IllegalStateException("Field not found in class hierarchy: " + name);
    }

    static MultivaluedMap<String, String> formParams(Map<String, String> entries) {
        MultivaluedMap<String, String> map = new MultivaluedHashMap<>();
        for (Map.Entry<String, String> e : entries.entrySet()) {
            map.putSingle(e.getKey(), e.getValue());
        }
        return map;
    }

    /**
     * Mimics Keycloak's request lifecycle around asynchronous OTP delivery so tests can observe
     * exactly when a send happens:
     * <ul>
     *   <li>the request session's transaction manager is active and records every
     *       {@code enlistAfterCompletion} hook instead of running it;</li>
     *   <li>{@link ExecutorsProvider} hands out a {@link QueuedExecutor} that only runs tasks
     *       when the test says so;</li>
     *   <li>{@link KeycloakSessionFactory#create()} returns {@code backgroundSession}, whose
     *       {@code realms()} resolves {@code realm} by id. Tests stub the background session's
     *       {@code users()} / providers as needed (it may be the request session itself).</li>
     * </ul>
     * Call {@link #commitRequest()} to play the end of the HTTP request (runs after-completion
     * hooks) and {@link #runDeliveries()} to let the background executor run.
     */
    static final class AsyncDeliveryHarness {
        final KeycloakTransactionManager requestTx = mock(KeycloakTransactionManager.class);
        final KeycloakTransactionManager backgroundTx = mock(KeycloakTransactionManager.class);
        final KeycloakSessionFactory factory = mock(KeycloakSessionFactory.class);
        final ExecutorsProvider executors = mock(ExecutorsProvider.class);
        final RealmProvider backgroundRealms = mock(RealmProvider.class);
        final KeycloakContext backgroundContext = mock(KeycloakContext.class);
        final QueuedExecutor executor = new QueuedExecutor();
        final List<KeycloakTransaction> afterCompletion = new ArrayList<>();
        final KeycloakSession backgroundSession;

        private AsyncDeliveryHarness(KeycloakSession requestSession, KeycloakSession backgroundSession,
                                     RealmModel realm, String realmId) {
            this.backgroundSession = backgroundSession;
            when(requestSession.getTransactionManager()).thenReturn(requestTx);
            when(requestTx.isActive()).thenReturn(true);
            doAnswer(inv -> {
                afterCompletion.add(inv.getArgument(0));
                return null;
            }).when(requestTx).enlistAfterCompletion(any(KeycloakTransaction.class));
            when(requestSession.getProvider(ExecutorsProvider.class)).thenReturn(executors);
            when(executors.getExecutor(anyString())).thenReturn(executor);
            when(requestSession.getKeycloakSessionFactory()).thenReturn(factory);

            when(factory.create()).thenReturn(backgroundSession);
            if (backgroundSession != requestSession) {
                when(backgroundSession.getTransactionManager()).thenReturn(backgroundTx);
                when(backgroundSession.getContext()).thenReturn(backgroundContext);
            }
            when(backgroundSession.realms()).thenReturn(backgroundRealms);
            when(backgroundRealms.getRealm(realmId)).thenReturn(realm);
        }

        static AsyncDeliveryHarness install(KeycloakSession requestSession, KeycloakSession backgroundSession,
                                            RealmModel realm, String realmId) {
            return new AsyncDeliveryHarness(requestSession, backgroundSession, realm, realmId);
        }

        /** End of the HTTP request: the request transaction committed, after-completion runs. */
        void commitRequest() {
            List<KeycloakTransaction> hooks = new ArrayList<>(afterCompletion);
            afterCompletion.clear();
            for (KeycloakTransaction tx : hooks) {
                if (!tx.isActive()) {
                    tx.begin();
                }
                tx.commit();
            }
        }

        /** End of the HTTP request with the request transaction rolled back. */
        void rollbackRequest() {
            List<KeycloakTransaction> hooks = new ArrayList<>(afterCompletion);
            afterCompletion.clear();
            for (KeycloakTransaction tx : hooks) {
                if (!tx.isActive()) {
                    tx.begin();
                }
                tx.rollback();
            }
        }

        /** Runs every task queued on the delivery executor; returns how many ran. */
        int runDeliveries() {
            return executor.runAll();
        }

        /** Request commit followed by the background delivery, i.e. "eventually". */
        void completeRequest() {
            commitRequest();
            runDeliveries();
        }
    }

    /** {@link java.util.concurrent.ExecutorService} that queues tasks until {@link #runAll()}. */
    static final class QueuedExecutor extends AbstractExecutorService {
        private final List<Runnable> queue = new ArrayList<>();

        @Override
        public synchronized void execute(Runnable command) {
            queue.add(command);
        }

        synchronized int pending() {
            return queue.size();
        }

        int runAll() {
            int ran = 0;
            while (true) {
                Runnable next;
                synchronized (this) {
                    if (queue.isEmpty()) {
                        return ran;
                    }
                    next = queue.remove(0);
                }
                next.run();
                ran++;
            }
        }

        @Override
        public void shutdown() {
        }

        @Override
        public List<Runnable> shutdownNow() {
            return List.of();
        }

        @Override
        public boolean isShutdown() {
            return false;
        }

        @Override
        public boolean isTerminated() {
            return false;
        }

        @Override
        public boolean awaitTermination(long timeout, TimeUnit unit) {
            return true;
        }
    }

    /**
     * Thread-safe in-memory {@link SingleUseObjectProvider} ({@code putIfAbsent} is atomic, like
     * Infinispan's) with hooks for reproducing read-modify-write races:
     * <ul>
     *   <li>{@link #freeze(String)} makes {@code get(key)} keep returning the current snapshot
     *       regardless of later writes — every subsequent caller behaves as if it had read the
     *       entry before any concurrent request wrote to it;</li>
     *   <li>{@link #gateReads(String, int)} blocks the first {@code n} {@code get(key)} callers
     *       until all {@code n} have read, so real threads all observe the same state.</li>
     * </ul>
     * TTLs are ignored. {@link #writes()} counts put/putIfAbsent/replace calls.
     */
    static final class ConcurrentInMemoryStore implements SingleUseObjectProvider {
        private final Map<String, Map<String, String>> data = new ConcurrentHashMap<>();
        private final Map<String, Map<String, String>> frozen = new ConcurrentHashMap<>();
        private final AtomicInteger writes = new AtomicInteger();
        private volatile String gatedKey;
        private volatile CountDownLatch gate;

        void freeze(String key) {
            Map<String, String> current = data.get(key);
            if (current != null) {
                frozen.put(key, new HashMap<>(current));
            }
        }

        void unfreeze(String key) {
            frozen.remove(key);
        }

        void gateReads(String key, int parties) {
            gatedKey = key;
            gate = new CountDownLatch(parties);
        }

        int writes() {
            return writes.get();
        }

        Map<String, Map<String, String>> snapshot() {
            return new HashMap<>(data);
        }

        @Override
        public void put(String key, long lifespanSeconds, Map<String, String> notes) {
            writes.incrementAndGet();
            data.put(key, new HashMap<>(notes));
        }

        @Override
        public Map<String, String> get(String key) {
            Map<String, String> value;
            Map<String, String> f = frozen.get(key);
            if (f != null) {
                value = new HashMap<>(f);
            } else {
                Map<String, String> v = data.get(key);
                value = v == null ? null : new HashMap<>(v);
            }
            CountDownLatch g = gate;
            if (g != null && key.equals(gatedKey)) {
                g.countDown();
                try {
                    if (!g.await(10, TimeUnit.SECONDS)) {
                        throw new IllegalStateException("read gate timed out");
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new IllegalStateException(e);
                }
            }
            return value;
        }

        @Override
        public Map<String, String> remove(String key) {
            return data.remove(key);
        }

        @Override
        public boolean replace(String key, Map<String, String> notes) {
            writes.incrementAndGet();
            return data.computeIfPresent(key, (k, old) -> new HashMap<>(notes)) != null;
        }

        @Override
        public boolean putIfAbsent(String key, long lifespanInSeconds) {
            writes.incrementAndGet();
            return data.putIfAbsent(key, new HashMap<>()) == null;
        }

        @Override
        public boolean contains(String key) {
            return data.containsKey(key);
        }

        @Override
        public void close() {
        }
    }
}
