/*
 * Copyright (c) 2014-2015 VMware, Inc. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License.  You may obtain a copy of
 * the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, without warranties or
 * conditions of any kind, EITHER EXPRESS OR IMPLIED.  See the License for the
 * specific language governing permissions and limitations under the License.
 */

package com.vmware.xenon.authn.common;

import static org.junit.Assert.assertEquals;

import java.net.URI;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Date;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Level;

import org.junit.rules.TemporaryFolder;

import com.vmware.xenon.common.Claims;
import com.vmware.xenon.common.Operation;
import com.vmware.xenon.common.Operation.AuthorizationContext;
import com.vmware.xenon.common.Operation.CompletionHandler;
import com.vmware.xenon.common.Service;
import com.vmware.xenon.common.ServiceDocument;
import com.vmware.xenon.common.ServiceHost;
import com.vmware.xenon.common.TaskState;
import com.vmware.xenon.common.UriUtils;
import com.vmware.xenon.common.Utils;
import com.vmware.xenon.common.test.TestContext;
import com.vmware.xenon.common.test.TestProperty;
import com.vmware.xenon.services.common.NodeGroupUtils;
import com.vmware.xenon.services.common.NodeState;
import com.vmware.xenon.services.common.ServiceUriPaths;
import com.vmware.xenon.services.common.TaskService;

public class AuthenticationVerificationHost extends AuthenticationServiceHost {

    private static final String VIDM_CONFIG_TEST_FILE = "C:/Users/srivastavaakash/Desktop/configuration.properties";

    private volatile TestContext context;

    private int timeoutSeconds = 30;

    private long testStartMicros;

    private long testEndMicros;

    private long expectedCompletionCount;

    private Throwable failure;

    private URI referer;

    private String lastTestName;

    private static final String providers = "Vidm";

    private static final String providerProperties = "C:/Users/srivastavaakash/Desktop/configuration.properties";

    /**
     * Command line argument indicating this is a stress test
     */
    public boolean isStressTest;

    /**
     * Command line argument for test duration, set for long running tests
     */
    public long testDurationSeconds;

    private TemporaryFolder temporaryFolder;

    public static AtomicInteger hostNumber = new AtomicInteger();

    private boolean isSingleton;

    public static AuthenticationVerificationHost create() {
        return new AuthenticationVerificationHost();
    }

    public static AuthenticationVerificationHost create(Integer port) throws Exception {
        AuthenticationHostArguments args = buildDefaultAuthenticationHostArguments(port);
        return initialize(new AuthenticationVerificationHost(), args);
    }

    public static AuthenticationHostArguments buildDefaultAuthenticationHostArguments(Integer port) {
        AuthenticationHostArguments args = new AuthenticationHostArguments();
        args.id = "host-" + hostNumber.incrementAndGet();
        args.port = port;
        args.sandbox = null;
        args.bindAddress = ServiceHost.LOOPBACK_ADDRESS;
        return args;
    }

    public static AuthenticationVerificationHost initialize(AuthenticationVerificationHost h, AuthenticationHostArguments args)
            throws Exception {
        if (args.sandbox == null) {
            h.setTemporaryFolder(new TemporaryFolder());
            h.getTemporaryFolder().create();
            args.sandbox = h.getTemporaryFolder().getRoot().toPath();
        }
        String[] hostArgs = convertFromArguments(args);
        try {
            h.initialize(hostArgs);
        } catch (Throwable e) {
            throw new RuntimeException(e);
        }
        return h;
    }

    public static String[] convertFromArguments(AuthenticationHostArguments args) {
        String[] hostArgs = {
                "--sandbox="
                        + args.sandbox,
                "--port=" + args.port,
                "--bindAddress=" + args.bindAddress,
                "--isAuthorizationEnabled=" + Boolean.TRUE.toString(),
                "--providers=" + providers,
                "--providerProperties=" + providerProperties,
        };
        return hostArgs;
    }

    public void tearDown() {
        stop();
        this.getTemporaryFolder().delete();
    }

    public void send(Operation op) {
        op.setReferer(getReferer());
        super.sendRequest(op);
    }

    /**
     * Creates a test wait context that can be nested and isolated from other wait contexts
     */
    public TestContext testCreate(int c) {
        return TestContext.create(c, TimeUnit.SECONDS.toMicros(this.timeoutSeconds));
    }

    /**
     * Starts a test context used for a single synchronous test execution for the entire host
     */
    public void testStart(long c) {
        if (this.isSingleton) {
            throw new IllegalStateException("Use testCreate on singleton, shared host instances");
        }
        String testName = buildTestNameFromStack();
        testStart(
                testName,
                EnumSet.noneOf(TestProperty.class), c);
    }

    public String buildTestNameFromStack() {
        StackTraceElement[] stack = new Exception().getStackTrace();
        String rootTestMethod = "";
        for (StackTraceElement s : stack) {
            if (s.getClassName().contains("vmware")) {
                rootTestMethod = s.getMethodName();
            }
        }
        String testName = rootTestMethod + ":" + stack[2].getMethodName();
        return testName;
    }

    public void testStart(String testName, EnumSet<TestProperty> properties, long c) {
        if (this.isSingleton) {
            throw new IllegalStateException("Use startTest on singleton, shared host instances");
        }
        if (this.context != null) {
            throw new IllegalStateException("A test is already started");
        }

        String negative = properties != null && properties.contains(TestProperty.FORCE_FAILURE)
                ? "(NEGATIVE)"
                : "";
        if (c > 1) {
            log("%sTest %s, iterations %d, started", negative, testName, c);
        }
        this.failure = null;
        this.expectedCompletionCount = c;
        this.testStartMicros = Utils.getNowMicrosUtc();
        this.context = TestContext.create((int) c, TimeUnit.SECONDS.toMicros(this.timeoutSeconds));
    }

    public void completeIteration() {
        if (this.isSingleton) {
            throw new IllegalStateException("Use startTest on singleton, shared host instances");
        }
        TestContext ctx = this.context;

        if (ctx == null) {
            String error = "testStart() and testWait() not paired properly" +
                    " or testStart(N) was called with N being less than actual completions";
            log(error);
            return;
        }
        ctx.completeIteration();
    }

    public void failIteration(Throwable e) {
        if (this.isSingleton) {
            throw new IllegalStateException("Use startTest on singleton, shared host instances");
        }
        if (isStopping()) {
            log("Received completion after stop");
            return;
        }

        TestContext ctx = this.context;

        if (ctx == null) {
            log("Test finished, ignoring completion. This might indicate wrong count was used in testStart(count)");
            return;
        }

        log("test failed: %s", e.toString());
        ctx.failIteration(e);
    }

    public void testWait(TestContext ctx) throws Throwable {
        ctx.await();
    }

    public void testWait() throws Throwable {
        testWait(new Exception().getStackTrace()[1].getMethodName(),
                this.timeoutSeconds);
    }

    public void testWait(String testName, int timeoutSeconds) throws Throwable {
        if (this.isSingleton) {
            throw new IllegalStateException("Use startTest on singleton, shared host instances");
        }

        TestContext ctx = this.context;
        if (ctx == null) {
            throw new IllegalStateException("testStart() was not called before testWait()");
        }

        if (this.expectedCompletionCount > 1) {
            log("Test %s, iterations %d, waiting ...", testName,
                    this.expectedCompletionCount);
        }

        try {
            ctx.await();
            this.testEndMicros = Utils.getNowMicrosUtc();
            if (this.expectedCompletionCount > 1) {
                log("Test %s, iterations %d, complete!", testName,
                        this.expectedCompletionCount);
            }
        } finally {
            this.context = null;
            this.lastTestName = testName;
        }
        return;

    }

    public void log(String fmt, Object... args) {
        super.log(Level.INFO, 3, fmt, args);
    }

    public <T> T getServiceState(EnumSet<TestProperty> props, Class<T> type, URI uri)
            throws Throwable {
        Map<URI, T> r = getServiceState(props, type, new URI[] { uri });
        return r.values().iterator().next();
    }

    /**
     * Retrieve in parallel, state from N services. This method will block execution until responses
     * are received or a failure occurs. It is not optimized for throughput measurements
     *
     * @param type
     * @param uris
     * @return
     * @throws Throwable
     */
    @SuppressWarnings("unchecked")
    public <T> Map<URI, T> getServiceState(EnumSet<TestProperty> props,
            Class<T> type,
            URI... uris) throws Throwable {

        if (type == null) {
            throw new IllegalArgumentException("type is required");
        }

        if (uris == null || uris.length == 0) {
            throw new IllegalArgumentException("uris are required");
        }

        Map<URI, T> results = new HashMap<>();
        TestContext ctx = testCreate(uris.length);
        Object[] state = new Object[1];

        for (URI u : uris) {
            Operation get = Operation
                    .createGet(u)
                    .setReferer(getReferer())
                    .setCompletion(
                            (o, e) -> {
                                try {
                                    if (e != null) {
                                        ctx.failIteration(e);
                                        return;
                                    }
                                    if (uris.length == 1) {
                                        state[0] = o.getBody(type);
                                    } else {
                                        synchronized (state) {
                                            ServiceDocument d = (ServiceDocument) o.getBody(type);
                                            results.put(
                                                    UriUtils.buildUri(o.getUri(),
                                                            d.documentSelfLink),
                                                    o.getBody(type));
                                        }
                                    }
                                    ctx.completeIteration();
                                } catch (Throwable ex) {
                                    log("Exception parsing state for %s: %s", o.getUri(),
                                            ex.toString());
                                    ctx.failIteration(ex);
                                }
                            });
            if (props != null && props.contains(TestProperty.FORCE_REMOTE)) {
                get.forceRemote();
            }
            if (props != null && props.contains(TestProperty.HTTP2)) {
                get.setConnectionSharing(true);
            }

            if (props != null && props.contains(TestProperty.DISABLE_CONTEXT_ID_VALIDATION)) {
                get.setContextId(TestProperty.DISABLE_CONTEXT_ID_VALIDATION.toString());
            }

            send(get);
        }

        testWait(ctx);
        if (uris.length == 1) {
            results.put(uris[0], (T) state[0]);
        }

        return results;
    }

    public URI getReferer() {
        if (this.referer == null) {
            this.referer = getUri();
        }
        return this.referer;
    }

    public void waitForServiceAvailable(String... links) throws Throwable {
        for (String link : links) {
            TestContext ctx = testCreate(1);
            this.registerForServiceAvailability(ctx.getCompletion(), link);
            ctx.await();
        }
    }

    public void waitForReplicatedFactoryServiceAvailable(URI u) throws Throwable {
        waitForReplicatedFactoryServiceAvailable(u, ServiceUriPaths.DEFAULT_NODE_SELECTOR);
    }

    public void waitForReplicatedFactoryServiceAvailable(URI u, String nodeSelectorPath)
            throws Throwable {
        waitFor("replicated available check time out for " + u, () -> {
            boolean[] isReady = new boolean[1];
            TestContext ctx = testCreate(1);
            NodeGroupUtils.checkServiceAvailability((o, e) -> {
                if (e != null) {
                    isReady[0] = false;
                    ctx.completeIteration();
                    return;
                }

                isReady[0] = true;
                ctx.completeIteration();
            }, this, u, nodeSelectorPath);
            ctx.await();
            return isReady[0];
        });
    }

    private Map<String, NodeState> peerHostIdToNodeState = new ConcurrentHashMap<>();
    private Map<URI, URI> peerNodeGroups = new ConcurrentHashMap<>();
    private Map<URI, AuthenticationVerificationHost> localPeerHosts = new ConcurrentHashMap<>();

    public Date getTestExpiration() {
        long duration = this.timeoutSeconds + this.testDurationSeconds;
        return new Date(new Date().getTime()
                + TimeUnit.SECONDS.toMillis(duration));
    }

    public void setStressTest(boolean isStressTest) {
        this.isStressTest = isStressTest;
        if (isStressTest) {
            this.timeoutSeconds = 600;
            this.setOperationTimeOutMicros(TimeUnit.SECONDS.toMicros(this.timeoutSeconds));
        } else {
            this.timeoutSeconds = (int) TimeUnit.MICROSECONDS.toSeconds(
                    ServiceHostState.DEFAULT_OPERATION_TIMEOUT_MICROS);
        }
    }

    public void tearDownInProcessPeers() {
        for (AuthenticationVerificationHost h : this.localPeerHosts.values()) {
            if (h == null) {
                continue;
            }
            stopHost(h);
        }
    }

    public void stopHost(AuthenticationVerificationHost host) {
        log("Stopping host %s (%s)", host.getUri(), host.getId());
        host.tearDown();
        this.peerHostIdToNodeState.remove(host.getId());
        this.peerNodeGroups.remove(host.getUri());
        this.localPeerHosts.remove(host.getUri());
    }

    public void setSystemAuthorizationContext() {
        setAuthorizationContext(getSystemAuthorizationContext());
    }

    @Override
    public void addPrivilegedService(Class<? extends Service> serviceType) {
        // Overriding just for test cases
        super.addPrivilegedService(serviceType);
    }

    @Override
    public void setAuthorizationContext(AuthorizationContext context) {
        super.setAuthorizationContext(context);
    }

    public void resetAuthorizationContext() {
        super.setAuthorizationContext(null);
    }

    /**
     * Inject user identity into operation context.
     *
     * @param userServicePath user document link
     */
    public AuthorizationContext assumeIdentity(String userServicePath) throws GeneralSecurityException {
        return assumeIdentity(userServicePath, null);
    }

    /**
     * Inject user identity into operation context.
     *
     * @param userServicePath user document link
     * @param properties custom properties in claims
     * @throws GeneralSecurityException any generic security exception
     */
    public AuthorizationContext assumeIdentity(String userServicePath,
            Map<String, String> properties) throws GeneralSecurityException {
        Claims.Builder builder = new Claims.Builder();
        builder.setSubject(userServicePath);
        builder.setProperties(properties);
        Claims claims = builder.getResult();
        String token = getTokenSigner().sign(claims);

        AuthorizationContext.Builder ab = AuthorizationContext.Builder.create();
        ab.setClaims(claims);
        ab.setToken(token);

        // Associate resulting authorization context with this thread
        AuthorizationContext authContext = ab.getResult();
        setAuthorizationContext(authContext);
        return authContext;
    }

    protected TemporaryFolder getTemporaryFolder() {
        return this.temporaryFolder;
    }

    public void setTemporaryFolder(TemporaryFolder temporaryFolder) {
        this.temporaryFolder = temporaryFolder;
    }

    /**
     * Decorates a {@link CompletionHandler} with a try/catch-all
     * and fails the current iteration on exception. Allow for calling
     * Assert.assert* directly in a handler.
     *
     * A safe handler will call completeIteration or failIteration exactly once.
     *
     * @param handler
     * @return
     */
    public CompletionHandler getSafeHandler(CompletionHandler handler) {
        return (o, e) -> {
            try {
                handler.handle(o, e);
                completeIteration();
            } catch (Throwable t) {
                failIteration(t);
            }
        };
    }

    /**
     * Creates a new service instance of type {@code service} via a {@code HTTP POST} to the service
     * factory URI (which is discovered automatically based on {@code service}). It passes {@code
     * state} as the body of the {@code POST}.
     * <p/>
     * See javadoc for <i>handler</i> param for important details on how to properly use this
     * method. If your test expects the service instance to be created successfully, you might use:
     * <pre>
     * String[] taskUri = new String[1];
     * CompletionHandler successHandler = getCompletionWithUri(taskUri);
     * sendFactoryPost(ExampleTaskService.class, new ExampleTaskServiceState(), successHandler);
     * </pre>
     *
     * @param service the type of service to create
     * @param state   the body of the {@code POST} to use to create the service instance
     * @param handler the completion handler to use when creating the service instance.
     *                <b>IMPORTANT</b>: This handler must properly call {@code host.failIteration()}
     *                or {@code host.completeIteration()}.
     * @param <T>     the state that represents the service instance
     */
    public <T extends ServiceDocument> void sendFactoryPost(Class<? extends Service> service,
            T state, CompletionHandler handler) throws Throwable {
        URI factoryURI = UriUtils.buildFactoryUri(this, service);
        log(Level.INFO, "Creating POST for [uri=%s] [body=%s]", factoryURI, state);
        Operation createPost = Operation.createPost(factoryURI)
                .setBody(state)
                .setCompletion(handler);

        testStart(1);
        send(createPost);
        testWait();
    }

    /**
     * Helper completion handler that:
     * <ul>
     * <li>Expects valid response to be returned; no exceptions when processing the operation</li>
     * <li>Expects a {@code ServiceDocument} to be returned in the response body. The response's
     * {@link ServiceDocument#documentSelfLink} will be stored in {@code storeUri[0]} so it can be
     * used for test assertions and logic</li>
     * </ul>
     *
     * @param storedLink The {@code documentSelfLink} of the created {@code ServiceDocument} will be
     *                 stored in {@code storedLink[0]} so it can be used for test assertions and
     *                 logic. This must be non-null and its length cannot be zero
     * @return a completion handler, handy for using in methods like {@link
     * #sendFactoryPost(Class, ServiceDocument, CompletionHandler)}
     */
    public CompletionHandler getCompletionWithSelflink(String[] storedLink) {
        if (storedLink == null || storedLink.length == 0) {
            throw new IllegalArgumentException(
                    "storeUri must be initialized and have room for at least one item");
        }

        return (op, ex) -> {
            if (ex != null) {
                failIteration(ex);
                return;
            }

            ServiceDocument response = op.getBody(ServiceDocument.class);
            if (response == null) {
                failIteration(new IllegalStateException(
                        "Expected non-null ServiceDocument in response body"));
                return;
            }

            log(Level.INFO, "Created service instance. [selfLink=%s] [kind=%s]",
                    response.documentSelfLink, response.documentKind);
            storedLink[0] = response.documentSelfLink;
            completeIteration();
        };
    }

    /**
     * Helper completion handler that:
     * <ul>
     * <li>Expects an exception when processing the handler; it is a {@code failIteration} if an
     * exception is <b>not</b> thrown.</li>
     * <li>The exception will be stored in {@code storeException[0]} so it can be used for test
     * assertions and logic.</li>
     * </ul>
     *
     * @param storeException the exception that occurred in completion handler will be stored in
     *                       {@code storeException[0]} so it can be used for test assertions and
     *                       logic. This must be non-null and its length cannot be zero.
     * @return a completion handler, handy for using in methods like {@link
     * #sendFactoryPost(Class, ServiceDocument, CompletionHandler)}
     */
    public CompletionHandler getExpectedFailureCompletionReturningThrowable(
            Throwable[] storeException) {
        if (storeException == null || storeException.length == 0) {
            throw new IllegalArgumentException(
                    "storeException must be initialized and have room for at least one item");
        }

        return (op, ex) -> {
            if (ex == null) {
                failIteration(new IllegalStateException("Failure expected"));
            }
            storeException[0] = ex;
            completeIteration();
        };
    }

    /**
     * Helper method that waits for {@code taskUri} to have a {@link TaskState.TaskStage} == {@code
     * TaskStage.FINISHED}.
     *
     * @param type    The class type that represent's the task's state
     * @param taskUri the URI of the task to wait for
     * @param <T>     the type that represent's the task's state
     * @return the state of the task once's it's {@code FINISHED}
     */
    public <T extends TaskService.TaskServiceState> T waitForFinishedTask(Class<T> type,
            String taskUri)
            throws Throwable {
        return waitForTask(type, taskUri, TaskState.TaskStage.FINISHED);
    }

    /**
     * Helper method that waits for {@code taskUri} to have a {@link TaskState.TaskStage} == {@code
     * TaskStage.FAILED}.
     *
     * @param type    The class type that represent's the task's state
     * @param taskUri the URI of the task to wait for
     * @param <T>     the type that represent's the task's state
     * @return the state of the task once's it s {@code FAILED}
     */
    public <T extends TaskService.TaskServiceState> T waitForFailedTask(Class<T> type,
            String taskUri)
            throws Throwable {
        return waitForTask(type, taskUri, TaskState.TaskStage.FAILED);
    }

    /**
     * Helper method that waits for {@code taskUri} to have a {@link TaskState.TaskStage} == {@code
     * expectedStage}.
     *
     * @param type          The class type of that represent's the task's state
     * @param taskUri       the URI of the task to wait for
     * @param expectedStage the stage we expect the task to eventually get to
     * @param <T>           the type that represent's the task's state
     * @return the state of the task once it's {@link TaskState.TaskStage} == {@code expectedStage}
     */
    public <T extends TaskService.TaskServiceState> T waitForTask(Class<T> type, String taskUri,
            TaskState.TaskStage expectedStage) throws Throwable {
        URI uri = UriUtils.buildUri(this, taskUri);

        // If the task's state ever reaches one of these "final" stages, we can stop waiting...
        List<TaskState.TaskStage> finalTaskStages = Arrays
                .asList(TaskState.TaskStage.CANCELLED, TaskState.TaskStage.FAILED,
                        TaskState.TaskStage.FINISHED, expectedStage);

        T state = null;
        for (int i = 0; i < 20; i++) {
            state = this.getServiceState(null, type, uri);
            if (state.taskInfo != null) {
                if (finalTaskStages.contains(state.taskInfo.stage)) {
                    break;
                }
            }
            Thread.sleep(250);
        }
        assertEquals("Task did not reach expected state", state.taskInfo.stage, expectedStage);
        return state;
    }

    public void setSingleton(boolean enable) {
        this.isSingleton = enable;
    }

    @FunctionalInterface
    public interface WaitHandler {
        boolean isReady() throws Throwable;
    }

    public void waitFor(String timeoutMsg, WaitHandler wh) throws Throwable {
        Date exp = getTestExpiration();
        while (new Date().before(exp)) {
            if (wh.isReady()) {
                return;
            }
            Thread.sleep(getMaintenanceIntervalMicros() / 1000);
        }
        throw new TimeoutException(timeoutMsg);
    }

}
