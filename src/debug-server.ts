import WebSocket, { RawData, WebSocketServer } from "ws";

import { CliOptions } from "./cli";
import type { FridaServerHandle } from "./frida-server";
import { Logger } from "./logger";
import { report_fatal_error } from "./process-guards";
import { close_window, is_window } from "./wechat-host";
import {
    inspectWin32WindowIdentity,
    snapshotTopLevelWindowsForPid,
} from "./win32-window-diagnostics";
import {
    MiniAppSession,
    AppServiceBinding,
    PendingSpawn,
    CdpFrameTree,
    INTERNAL_CDP_TIMEOUT_MS,
    bufferToHexString,
    rawDataToBuffer,
    touchSession,
    createSession,
    flattenFrameTree,
} from "./session";

const codex = require("./third-party/RemoteDebugCodex.js");
const messageProto = require("./third-party/WARemoteDebugProtobuf.js");
const FOREGROUND_KEEP_ALIVE_MS = 3_000;
const MINIAPP_WINDOW_WAIT_INTERVAL_MS = 100;
const SESSION_HEALTHCHECK_INTERVAL_MS = 4_000;
const SESSION_HEALTHCHECK_IDLE_MS = 12_000;
const BOOTSTRAP_RETRY_INTERVAL_MS = 1_500;
const BOOTSTRAP_MAX_RETRIES = 3;
const CLOSE_CDP_GRACE_MS = 2_000;
const WINDOW_CENSUS_LAUNCH_GRACE_MS = 3_000;

const ACCOUNT_INFO_EXPRESSION = `
(() => {
    try {
        const accountInfo = globalThis.wx &&
            typeof globalThis.wx.getAccountInfoSync === "function"
            ? globalThis.wx.getAccountInfoSync()
            : null;
        return accountInfo === undefined ? null : accountInfo;
    } catch (error) {
        return {
            __error: error instanceof Error ? error.message : String(error),
        };
    }
})()
`.trim();

const EXIT_MINIPROGRAM_EXPRESSION = `
(() => {
    try {
        const api = globalThis.wx &&
            typeof globalThis.wx.exitMiniProgram === "function"
            ? globalThis.wx.exitMiniProgram
            : null;
        if (api) {
            api({});
            return "exit-requested";
        }
        return "exit-api-unavailable";
    } catch (error) {
        return "exit-error";
    }
})()
`.trim();

const isRecoverableAppContextError = (error: unknown) => {
    const message =
        error instanceof Error ? error.message : String(error ?? "");
    return (
        message.includes("Cannot find context") ||
        message.includes("Execution context was destroyed") ||
        message.includes("Inspected target navigated or closed") ||
        message.includes("No session with given id") ||
        message.includes("Target closed")
    );
};

export const isDeadSessionFailure = (error: unknown) => {
    const message = formatErrorMessage(error);
    return (
        message.includes("miniapp debug socket unavailable") ||
        message.includes("miniapp disconnected") ||
        message.includes("CDP timeout") ||
        message.includes("app context became unavailable") ||
        message.includes("app target binding unavailable") ||
        message.includes("unable to find app target") ||
        message.includes("unable to attach app target") ||
        message.includes("unable to find app frame") ||
        message.includes("app frame binding unavailable") ||
        isRecoverableAppContextError(error)
    );
};

const formatErrorMessage = (error: unknown) =>
    error instanceof Error ? error.message : String(error ?? "");

const shouldDisableForegroundCommand = (error: unknown) => {
    const message = formatErrorMessage(error);
    return (
        message.includes("wasn't found") ||
        message.includes("was not found") ||
        message.includes("Unknown method") ||
        message.includes("Method not found") ||
        message.includes("not supported")
    );
};

export const debug_server = (
    options: CliOptions,
    logger: Logger,
    sessions: Map<string, MiniAppSession>,
    pendingSpawns: Map<string, PendingSpawn>,
    fridaServer: Pick<
        FridaServerHandle,
        | "listMiniAppWindowCandidates"
        | "getMiniAppWindowCursor"
        | "getStatus"
    >,
) => {
    const debugSocketSessions = new Map<WebSocket, MiniAppSession>();
    const foregroundKeepAliveActive = new WeakSet<MiniAppSession>();
    const healthCheckRequested = new WeakSet<MiniAppSession>();
    const healthCheckInFlight = new WeakSet<MiniAppSession>();
    const disabledForegroundCommands = new WeakMap<MiniAppSession, Set<string>>();
    const capturedWindowsByAppId = new Map<
        string,
        MiniAppSession["windowIdentity"] & {}
    >();
    const wss = new WebSocketServer({ port: options.debugPort });
    wss.on("error", (error) => {
        report_fatal_error(logger, "[server] debug server error", error);
    });
    logger.info(
        `[server] debug server running on ws://localhost:${options.debugPort}`,
    );
    logger.info(`[server] debug server waiting for miniapp to connect...`);

    const listDebuggableSessions = () => {
        const selected = new Map<string, MiniAppSession>();
        for (const session of new Set(sessions.values())) {
            if (
                session.state !== "ready" ||
                session.debugSocket?.readyState !== WebSocket.OPEN ||
                session.appService === undefined
            ) {
                continue;
            }
            const appid = session.requestedAppId ?? session.id;
            const existing = selected.get(appid);
            if (
                !existing ||
                session.evaluationSuccesses > existing.evaluationSuccesses ||
                (session.evaluationSuccesses ===
                    existing.evaluationSuccesses &&
                    session.evaluationFailures < existing.evaluationFailures) ||
                (session.evaluationSuccesses ===
                    existing.evaluationSuccesses &&
                    session.evaluationFailures ===
                        existing.evaluationFailures &&
                    session.createdAt < existing.createdAt)
            ) {
                selected.set(appid, session);
            }
        }
        return Array.from(selected.values());
    };

    const bindPendingSpawn = (
        session: MiniAppSession,
        pendingSpawn: PendingSpawn,
    ) => {
        session.requestedAppId = pendingSpawn.appid;
        session.launchId = pendingSpawn.id;
        session.launchStartedAt = pendingSpawn.createdAt;
        session.launchWindowCursor = pendingSpawn.windowCursor;
        session.launchAppIdConfirmed = false;
        pendingSpawn.boundSessionId = session.id;
        session.title = pendingSpawn.appid;
        logger.info(
            `[miniapp] bound pending spawn ${pendingSpawn.appid} to ${session.id}`,
        );
    };

    const resolvePendingSpawn = (appid: string, session: MiniAppSession) => {
        const pendingSpawn = pendingSpawns.get(appid);
        if (!pendingSpawn) {
            return;
        }
        if (session.launchId !== pendingSpawn.id) {
            logger.info(
                `[miniapp] refusing to resolve pending spawn ${appid} from unrelated session ${session.id}`,
            );
            return;
        }

        clearTimeout(pendingSpawn.timeout);
        pendingSpawns.delete(appid);

        for (const waiter of pendingSpawn.waiters) {
            waiter.resolve(session);
        }
        pendingSpawn.waiters.clear();
    };

    const rejectPendingSpawn = (appid: string, error: Error) => {
        const pendingSpawn = pendingSpawns.get(appid);
        if (!pendingSpawn) {
            return;
        }

        clearTimeout(pendingSpawn.timeout);
        pendingSpawns.delete(appid);

        for (const waiter of pendingSpawn.waiters) {
            waiter.reject(error);
        }
        pendingSpawn.waiters.clear();
    };

    const rejectSessionPendingSpawn = (
        session: MiniAppSession,
        error: Error,
    ) => {
        const pendingSpawn = session.requestedAppId
            ? pendingSpawns.get(session.requestedAppId)
            : undefined;
        if (pendingSpawn && pendingSpawn.id === session.launchId) {
            rejectPendingSpawn(pendingSpawn.appid, error);
        }
    };

    const removeSession = (session: MiniAppSession) => {
        for (const [id, currentSession] of sessions.entries()) {
            if (currentSession === session) {
                sessions.delete(id);
            }
        }
    };

    const rejectPendingWork = (session: MiniAppSession, message: string) => {
        for (const [id, pending] of session.pendingCommands.entries()) {
            clearTimeout(pending.timeout);
            pending.reject(new Error(message));
            session.pendingCommands.delete(id);
        }

        for (const [key, pending] of session.pendingContexts.entries()) {
            clearTimeout(pending.timeout);
            pending.reject(new Error(message));
            session.pendingContexts.delete(key);
        }
    };

    const stopForegroundKeepAlive = (session: MiniAppSession) => {
        if (session.foregroundKeepAlive) {
            clearInterval(session.foregroundKeepAlive);
            session.foregroundKeepAlive = undefined;
        }
    };

    const stopSessionHealthCheck = (session: MiniAppSession) => {
        if (session.healthCheck) {
            clearInterval(session.healthCheck);
            session.healthCheck = undefined;
        }
        healthCheckRequested.delete(session);
        healthCheckInFlight.delete(session);
    };

    const closeWebSocket = (
        socket: WebSocket | undefined,
        code: number,
        reason: string,
        force = false,
    ) => {
        if (!socket || socket.readyState === WebSocket.CLOSED) {
            return;
        }

        if (force || socket.readyState === WebSocket.CONNECTING) {
            socket.terminate();
            return;
        }

        try {
            socket.close(code, reason.slice(0, 120));
            const timeout = setTimeout(() => {
                if (socket.readyState !== WebSocket.CLOSED) {
                    socket.terminate();
                }
            }, 500);
            timeout.unref();
            socket.once("close", () => clearTimeout(timeout));
        } catch (error) {
            socket.terminate();
        }
    };

    const detachSession = (session: MiniAppSession, reason: string) => {
        const debugSocket = session.debugSocket;
        const devtoolsSocket = session.devtoolsSocket;

        session.debugSocket = undefined;
        session.devtoolsSocket = undefined;
        session.appService = undefined;
        session.attached = false;
        session.state = "closing";
        session.lastError = reason;
        touchSession(session);

        stopForegroundKeepAlive(session);
        stopSessionHealthCheck(session);
        rejectPendingWork(session, reason);
        removeSession(session);

        if (debugSocket) {
            debugSocketSessions.delete(debugSocket);
        }

        closeWebSocket(devtoolsSocket, 1001, reason);
        closeWebSocket(debugSocket, 1011, reason, true);
    };

    const hasLiveWindow = (session: MiniAppSession) => {
        if (session.windowHandle === undefined) {
            return false;
        }
        try {
            return is_window(session.windowHandle);
        } catch (error) {
            logger.error(
                `[miniapp] failed to validate cached hwnd for ${session.id}:`,
                error,
            );
            return false;
        }
    };

    // Ends a session without requiring window identity. The session is
    // removed unless a live, known HWND is retained so an explicit close can
    // still reach it. A retained session never blocks a new launch.
    const teardownSession = (session: MiniAppSession, reason: string) => {
        const debugSocket = session.debugSocket;
        const devtoolsSocket = session.devtoolsSocket;
        session.debugSocket = undefined;
        session.devtoolsSocket = undefined;
        session.appService = undefined;
        session.attached = false;
        session.state = "closing";
        session.lastError = reason;
        touchSession(session);

        stopForegroundKeepAlive(session);
        stopSessionHealthCheck(session);
        rejectPendingWork(session, reason);

        const retainedForExplicitClose = hasLiveWindow(session);
        if (!retainedForExplicitClose) {
            removeSession(session);
        }

        if (debugSocket) {
            debugSocketSessions.delete(debugSocket);
        }

        closeWebSocket(devtoolsSocket, 1001, reason);
        closeWebSocket(debugSocket, 1011, reason, true);
        return retainedForExplicitClose;
    };

    const sleep = (ms: number) =>
        new Promise<void>((resolve) => setTimeout(resolve, ms));

    const retainPendingLaunchWindow = (pendingSpawn: PendingSpawn) => {
        const existing = Array.from(sessions.values()).find(
            (session) =>
                session.id === pendingSpawn.appid ||
                session.requestedAppId === pendingSpawn.appid,
        );
        if (existing) {
            return existing;
        }

        const fridaStatus = fridaServer.getStatus();
        if (fridaStatus.pid === null) {

            return undefined;
        }

        const candidates = fridaServer.listMiniAppWindowCandidates({
            afterSequence: pendingSpawn.windowCursor,
            createdAfter: pendingSpawn.createdAt,
            createdBefore: Date.now(),
            pid: fridaStatus.pid,
        });
        if (candidates.length !== 1) {

            return undefined;
        }

        const candidate = candidates[0];
        if (candidate.pid === 0 || candidate.tid === 0) {
            return undefined;
        }
        const inspection = inspectWin32WindowIdentity(
            candidate.handle,
            candidate.pid,
        );
        const window = inspection.snapshot;
        const expectedHwnd = `0x${candidate.handle.toString(16)}`;
        if (
            !inspection.windowCheckCompleted ||
            !inspection.windowExists ||
            !window ||
            !window.visible ||
            window.hwnd.toLowerCase() !== expectedHwnd ||
            window.pid !== candidate.pid ||
            window.tid !== candidate.tid ||
            (candidate.className !== undefined &&
                window.className !== candidate.className)
        ) {

            return undefined;
        }

        const session = createSession(pendingSpawn.appid);
        session.state = "closing";
        session.lastError =
            "miniapp launched a window but did not attach to the debugger";
        session.launchId = pendingSpawn.id;
        session.launchStartedAt = pendingSpawn.createdAt;
        session.launchWindowCursor = pendingSpawn.windowCursor;
        session.launchAppIdConfirmed = false;
        session.windowHandle = candidate.handle;
        session.windowIdentity = {
            handle: candidate.handle,
            pid: window.pid,
            tid: window.tid,
            className: window.className,
            launchId: pendingSpawn.id,
            verifiedAt: Date.now(),
        };
        touchSession(session);
        sessions.set(session.id, session);

        return session;
    };

    const applyWindowIdentity = (
        session: MiniAppSession,
        window: {
            handle: number;
            pid: number;
            tid: number;
            className: string;
            title: string;
        },
        evidence: "new-window-since-launch" | "cached-window-revalidated",
    ) => {
        session.windowHandle = window.handle;
        session.windowIdentity = {
            handle: window.handle,
            pid: window.pid,
            tid: window.tid,
            className: window.className,
            title: window.title,
            launchId: session.launchId ?? "",
            verifiedAt: Date.now(),
        };
        if (session.requestedAppId) {
            capturedWindowsByAppId.set(
                session.requestedAppId,
                session.windowIdentity,
            );
        }
        touchSession(session);
        logger.info(
            `[miniapp] captured window identity for ${session.id} (${evidence}): ` +
                `0x${window.handle.toString(16)} (pid=${window.pid}, tid=${window.tid})`,
        );
    };

    // Capture the miniapp window from hook-reported lifecycle events. A
    // launch's window is the single visible miniapp window the hook reported
    // as created/shown after the launch began. For an already-open singleton
    // (no new window), a cached appid->window mapping is reused only after
    // field-by-field revalidation (hwnd, pid, tid, class, title).
    const captureWindowIdentity = (session: MiniAppSession) => {
        if (session.windowIdentity) {
            return;
        }
        const hostPid = fridaServer.getStatus().pid;
        if (hostPid === null) {
            return;
        }

        const referenceStart =
            session.launchStartedAt ??
            (session.createdAt - WINDOW_CENSUS_LAUNCH_GRACE_MS);
        const candidates = fridaServer
            .listMiniAppWindowCandidates({
                afterSequence: session.launchWindowCursor ?? 0,
                createdAfter:
                    referenceStart - WINDOW_CENSUS_LAUNCH_GRACE_MS,
                createdBefore: Date.now() + 1_000,
                pid: hostPid,
            })
            .filter(
                (candidate) =>
                    candidate.visible &&
                    candidate.className === "Chrome_WidgetWin_0" &&
                    candidate.title.trim().length > 0,
            );

        if (candidates.length === 1) {
            applyWindowIdentity(
                session,
                candidates[0],
                "new-window-since-launch",
            );
            return;
        }

        const cached = session.requestedAppId
            ? capturedWindowsByAppId.get(session.requestedAppId)
            : undefined;
        if (!cached) {
            return;
        }
        const expectedHwnd = `0x${cached.handle.toString(16)}`;
        const current = snapshotTopLevelWindowsForPid(hostPid).find(
            (window) =>
                window.hwnd.toLowerCase() === expectedHwnd &&
                window.pid === cached.pid &&
                window.tid === cached.tid &&
                window.className === cached.className &&
                window.title === cached.title,
        );
        if (current) {
            applyWindowIdentity(
                session,
                {
                    handle: cached.handle,
                    pid: current.pid,
                    tid: current.tid,
                    className: current.className,
                    title: current.title,
                },
                "cached-window-revalidated",
            );
        }
    };

    const sendMiniAppCdpMessage = (session: MiniAppSession, message: string) => {
        if (!session.debugSocket || session.debugSocket.readyState !== WebSocket.OPEN) {
            throw new Error("miniapp debug socket unavailable");
        }

        const rawPayload = {
            jscontext_id: "",
            op_id: Math.round(100 * Math.random()),
            payload: message,
        };
        logger.main_debug(rawPayload);
        const wrappedData = codex.wrapDebugMessageData(
            rawPayload,
            "chromeDevtools",
            0,
        );
        const outData = {
            seq: ++session.messageCounter,
            category: "chromeDevtools",
            data: wrappedData.buffer,
            compressAlgo: 0,
            originalSize: wrappedData.originalSize,
        };
        const encodedData =
            messageProto.mmbizwxadevremote.WARemoteDebug_DebugMessage.encode(
                outData,
            ).finish();
        session.debugSocket.send(encodedData, { binary: true });
        touchSession(session);
    };

    const sendInternalCommand = async (
        session: MiniAppSession,
        method: string,
        params?: Record<string, unknown>,
        sessionId?: string,
    ) => {
        const id = ++session.internalCommandCounter;
        const payload: Record<string, unknown> = {
            id,
            method,
        };
        if (params !== undefined) {
            payload.params = params;
        }
        if (sessionId !== undefined) {
            payload.sessionId = sessionId;
        }

        const message = JSON.stringify(payload);
        const response = await new Promise<any>((resolve, reject) => {
            const timeout = setTimeout(() => {
                session.pendingCommands.delete(id);
                reject(new Error(`CDP timeout for ${method}`));
            }, INTERNAL_CDP_TIMEOUT_MS);
            session.pendingCommands.set(id, { resolve, reject, timeout });
            try {
                sendMiniAppCdpMessage(session, message);
            } catch (error) {
                clearTimeout(timeout);
                session.pendingCommands.delete(id);
                reject(error);
            }
        });

        if (response.error) {
            const messageText =
                response.error.message || `CDP error for ${method}`;
            throw new Error(messageText);
        }

        return response;
    };

    const getDisabledForegroundCommands = (session: MiniAppSession) => {
        let disabledCommands = disabledForegroundCommands.get(session);
        if (!disabledCommands) {
            disabledCommands = new Set<string>();
            disabledForegroundCommands.set(session, disabledCommands);
        }
        return disabledCommands;
    };

    const sendForegroundCommand = async (
        session: MiniAppSession,
        method: string,
        params?: Record<string, unknown>,
        sessionId?: string,
    ) => {
        const commandKey = sessionId ? `${sessionId}:${method}` : method;
        const disabledCommands = getDisabledForegroundCommands(session);
        if (disabledCommands.has(commandKey)) {
            return;
        }

        try {
            await sendInternalCommand(session, method, params, sessionId);
        } catch (error) {
            logger.main_debug(
                `[miniapp] foreground command failed (${session.id}, ${method}):`,
                error,
            );
            if (shouldDisableForegroundCommand(error)) {
                disabledCommands.add(commandKey);
            } else {
                healthCheckRequested.add(session);
            }
        }
    };

    const applyForegroundState = async (
        session: MiniAppSession,
        appService: AppServiceBinding,
    ) => {
        if (
            session.state === "closing" ||
            !session.debugSocket ||
            session.debugSocket.readyState !== WebSocket.OPEN
        ) {
            return;
        }

        if (foregroundKeepAliveActive.has(session)) {
            return;
        }

        foregroundKeepAliveActive.add(session);
        try {
            await sendForegroundCommand(
                session,
                "Emulation.setFocusEmulationEnabled",
                { enabled: true },
                appService.sessionId,
            );
            await sendForegroundCommand(
                session,
                "Emulation.setIdleOverride",
                {
                    isUserActive: true,
                    isScreenUnlocked: true,
                },
                appService.sessionId,
            );
            await sendForegroundCommand(
                session,
                "Page.setWebLifecycleState",
                { state: "active" },
                appService.sessionId,
            );
            touchSession(session);
        } finally {
            foregroundKeepAliveActive.delete(session);
        }
    };

    const startForegroundKeepAlive = (session: MiniAppSession) => {
        if (session.foregroundKeepAlive) {
            return;
        }

        session.foregroundKeepAlive = setInterval(() => {
            const appService = session.appService;
            if (!appService) {
                return;
            }

            void applyForegroundState(session, appService).catch((error) => {
                logger.info(
                    `[miniapp] foreground keepalive paused for ${session.id}: ${formatErrorMessage(error)}`,
                );
            });
        }, FOREGROUND_KEEP_ALIVE_MS);
        session.foregroundKeepAlive.unref();
    };

    const waitForExecutionContext = (
        session: MiniAppSession,
        sessionId: string,
        frameId?: string,
    ) =>
        new Promise<number>((resolve, reject) => {
            const timeout = setTimeout(() => {
                session.pendingContexts.delete(sessionId);
                reject(new Error("execution context timeout"));
            }, INTERNAL_CDP_TIMEOUT_MS);
            session.pendingContexts.set(sessionId, {
                frameId,
                resolve,
                reject,
                timeout,
            });
        });

    const findAppTargetId = async (session: MiniAppSession) => {
        if (session.appService?.targetId) {
            return session.appService.targetId;
        }

        const targetResponse = await sendInternalCommand(
            session,
            "Target.getTargets",
        );
        const targetInfos = targetResponse.result?.targetInfos || [];
        const targetInfo = targetInfos.find(
            (candidate: any) => String(candidate.title || "") === "AppIndex",
        );
        if (!targetInfo || typeof targetInfo.targetId !== "string") {
            throw new Error("unable to find app target");
        }
        return targetInfo.targetId;
    };

    const discoverAppContext = async (
        session: MiniAppSession,
        options?: {
            forceAttach?: boolean;
            forceContextRefresh?: boolean;
        },
    ) => {
        const existingBinding = session.appService;
        let targetId = existingBinding?.targetId;
        let appServiceSessionId = existingBinding?.sessionId;
        let frameId = existingBinding?.frameId;
        let contextId = existingBinding?.contextId;

        if (options?.forceAttach || !targetId || !appServiceSessionId) {
            targetId = await findAppTargetId(session);

            const attachResponse = await sendInternalCommand(
                session,
                "Target.attachToTarget",
                {
                    targetId,
                    flatten: true,
                },
            );
            appServiceSessionId = attachResponse.result?.sessionId;
            if (typeof appServiceSessionId !== "string") {
                throw new Error("unable to attach app target");
            }
            frameId = undefined;
            contextId = undefined;
        }

        if (!targetId || !appServiceSessionId) {
            throw new Error("app target binding unavailable");
        }

        if (!frameId) {
            const frameTreeResponse = await sendInternalCommand(
                session,
                "Page.getFrameTree",
                {},
                appServiceSessionId,
            );
            const frames = flattenFrameTree(
                frameTreeResponse.result?.frameTree as CdpFrameTree | undefined,
            );
            const appContextFrame = frames.find(
                (frame) => String(frame?.name || "") === "appContext",
            );
            if (!appContextFrame || typeof appContextFrame.id !== "string") {
                throw new Error("unable to find app frame");
            }
            frameId = appContextFrame.id;
        }

        if (!frameId) {
            throw new Error("app frame binding unavailable");
        }

        if (
            contextId === undefined ||
            options?.forceContextRefresh ||
            options?.forceAttach
        ) {
            const [resolvedContextId] = await Promise.all([
                waitForExecutionContext(
                    session,
                    appServiceSessionId,
                    frameId,
                ),
                sendInternalCommand(
                    session,
                    "Runtime.enable",
                    {},
                    appServiceSessionId,
                ),
            ]);
            contextId = resolvedContextId;
        }

        const appService = {
            targetId,
            sessionId: appServiceSessionId,
            frameId,
            contextId,
        };
        session.appService = appService;
        await applyForegroundState(session, appService);
        if (session.state === "closing" || session.appService !== appService) {
            throw new Error("app context became unavailable");
        }
        touchSession(session);
        return appService;
    };

    const resolveSessionAppId = async (session: MiniAppSession) => {
        const appContext = await discoverAppContext(session, {
            forceAttach: true,
            forceContextRefresh: true,
        });
        const accountInfoResponse = await sendInternalCommand(
            session,
            "Runtime.evaluate",
            {
                expression: ACCOUNT_INFO_EXPRESSION,
                contextId: appContext.contextId,
                awaitPromise: true,
                returnByValue: true,
            },
            appContext.sessionId,
        );
        const accountInfoValue = accountInfoResponse.result?.result?.value;
        const appId = accountInfoValue?.miniProgram?.appId;
        const appidValue =
            typeof appId === "string" && appId.trim().length > 0
                ? appId.trim()
                : "";

        logger.info(
            `[miniapp] account info for ${session.id}: ` +
                `appid=${appidValue || "<blank>"}, ` +
                `env=${accountInfoValue?.miniProgram?.envVersion ?? "unknown"}, ` +
                `version=${accountInfoValue?.miniProgram?.version ?? "unknown"}`,
        );
        if (!appidValue) {
            throw new Error(
                "miniapp did not return a valid appid; runtime is not running correctly",
            );
        }
        session.title = appidValue;
        touchSession(session);
        return appidValue;
    };

    const evaluateInAppContext = async (
        session: MiniAppSession,
        expression: string,
    ) => {
        const sendEvaluate = async (forceRefresh = false) => {
            const appContext = await discoverAppContext(session, {
                forceAttach: forceRefresh,
                forceContextRefresh: forceRefresh,
            });
            const response = await sendInternalCommand(
                session,
                "Runtime.evaluate",
                {
                    expression,
                    contextId: appContext.contextId,
                    awaitPromise: true,
                    returnByValue: true,
                },
                appContext.sessionId,
            );
            touchSession(session);
            return {
                result: response.result?.result ?? null,
                exceptionDetails: response.result?.exceptionDetails ?? null,
                context: {
                    targetId: appContext.targetId,
                    sessionId: appContext.sessionId,
                    frameId: appContext.frameId,
                    contextId: appContext.contextId,
                },
            };
        };

        try {
            let result;
            try {
                result = await sendEvaluate(false);
            } catch (error) {
                if (!isRecoverableAppContextError(error)) {
                    throw error;
                }

                logger.info(
                    `[miniapp] refreshing appContext for ${session.id} after evaluate failure`,
                );
                result = await sendEvaluate(true);
            }
            session.evaluationSuccesses += 1;
            session.lastEvaluationSucceededAt = Date.now();
            touchSession(session);

            return result;
        } catch (error) {
            session.evaluationFailures += 1;
            session.lastEvaluationFailedAt = Date.now();
            touchSession(session);
            healthCheckRequested.add(session);

            throw error;
        }
    };

    const runSessionHealthCheck = async (session: MiniAppSession) => {
        if (healthCheckInFlight.has(session)) {
            return;
        }
        if (
            session.state !== "ready" ||
            !session.debugSocket ||
            session.debugSocket.readyState !== WebSocket.OPEN
        ) {
            return;
        }

        healthCheckInFlight.add(session);
        try {
            const probeSession = async () => {
                await sendInternalCommand(session, "Target.getTargets");
                const appService = session.appService;
                if (appService) {
                    await sendInternalCommand(
                        session,
                        "Runtime.evaluate",
                        {
                            expression: "1",
                            contextId: appService.contextId,
                            returnByValue: true,
                        },
                        appService.sessionId,
                    );
                }
            };
            const requested = healthCheckRequested.has(session);
            healthCheckRequested.delete(session);
            const idleMs =
                Date.now() -
                (session.lastMessageReceivedAt ?? session.updatedAt);
            if (!requested && idleMs < SESSION_HEALTHCHECK_IDLE_MS) {
                return;
            }

            try {
                await probeSession();
                touchSession(session);
                return;
            } catch (error) {
                logger.info(
                    `[miniapp] health check failed for ${session.id}: ${formatErrorMessage(error)}; attempting recovery`,
                );

                try {
                    await discoverAppContext(session, {
                        forceAttach: true,
                        forceContextRefresh: true,
                    });
                    await probeSession();
                    touchSession(session);
                    logger.info(`[miniapp] recovery succeeded for ${session.id}`);

                } catch (recoveryError) {
                    logger.error(
                        `[miniapp] recovery failed for ${session.id}:`,
                        recoveryError,
                    );

                    teardownSession(
                        session,
                        "miniapp stopped responding to commands",
                    );
                }
            }
        } finally {
            healthCheckInFlight.delete(session);
        }
    };

    const startSessionHealthCheck = (session: MiniAppSession) => {
        if (session.healthCheck) {
            return;
        }
        session.healthCheck = setInterval(() => {
            void runSessionHealthCheck(session).catch((error) => {
                logger.error(
                    `[miniapp] health check error for ${session.id}:`,
                    error,
                );
            });
        }, SESSION_HEALTHCHECK_INTERVAL_MS);
        session.healthCheck.unref();
    };

    const rekeySessionByAppId = (session: MiniAppSession, appid: string) => {
        if (session.id === appid) {
            if (!sessions.has(appid)) {
                sessions.set(appid, session);
            }
            return "canonical" as const;
        }

        const existing = sessions.get(appid);
        if (existing && existing !== session) {
            const existingUsable =
                existing.state === "ready" &&
                existing.debugSocket?.readyState === WebSocket.OPEN &&
                existing.appService !== undefined;
            if (existingUsable) {
                logger.info(
                    `[miniapp] alternate attachment ready for ${appid}: keeping canonical ${existing.traceId}, candidate ${session.traceId}`,
                );

                return "alternate" as const;
            }

            session.launchId ??= existing.launchId;
            session.launchStartedAt ??= existing.launchStartedAt;
            session.launchWindowCursor ??= existing.launchWindowCursor;
            session.launchAppIdConfirmed ||= existing.launchAppIdConfirmed;
            session.windowHandle ??= existing.windowHandle;
            session.windowIdentity ??= existing.windowIdentity;
            sessions.delete(appid);
            existing.state = "closing";
            existing.lastError = "superseded by a working attachment";
            stopForegroundKeepAlive(existing);
            stopSessionHealthCheck(existing);
            touchSession(existing);
            logger.info(
                `[miniapp] replacing stale attachment for ${appid}: ${existing.traceId} -> ${session.traceId}`,
            );

        }

        const previousId = session.id;
        sessions.delete(previousId);
        session.id = appid;
        sessions.set(appid, session);
        return "canonical" as const;
    };

    const promoteSessionAttachment = (
        appid: string,
        candidate: MiniAppSession,
    ) => {
        const canonical = sessions.get(appid);
        const candidateSocket = candidate.debugSocket;
        if (
            !canonical ||
            canonical === candidate ||
            candidate.state !== "ready" ||
            !candidate.appService ||
            !candidateSocket ||
            candidateSocket.readyState !== WebSocket.OPEN
        ) {
            return canonical ?? candidate;
        }

        const oldSocket = canonical.debugSocket;
        const oldDevtoolsSocket = canonical.devtoolsSocket;
        stopForegroundKeepAlive(canonical);
        stopForegroundKeepAlive(candidate);
        stopSessionHealthCheck(canonical);
        stopSessionHealthCheck(candidate);
        rejectPendingWork(
            canonical,
            "miniapp attachment superseded by a successful candidate",
        );

        canonical.debugSocket = candidateSocket;
        canonical.appService = candidate.appService;
        canonical.state = "ready";
        canonical.lastError = undefined;
        canonical.messageCounter = Math.max(
            canonical.messageCounter,
            candidate.messageCounter,
        );
        canonical.internalCommandCounter = Math.max(
            canonical.internalCommandCounter,
            candidate.internalCommandCounter,
        );
        canonical.evaluationSuccesses += candidate.evaluationSuccesses;
        canonical.evaluationFailures += candidate.evaluationFailures;
        canonical.lastEvaluationSucceededAt =
            candidate.lastEvaluationSucceededAt;
        canonical.lastEvaluationFailedAt = candidate.lastEvaluationFailedAt;
        canonical.windowHandle ??= candidate.windowHandle;
        canonical.windowIdentity ??= candidate.windowIdentity;
        canonical.launchId ??= candidate.launchId;
        canonical.launchStartedAt ??= candidate.launchStartedAt;
        canonical.launchWindowCursor ??= candidate.launchWindowCursor;
        canonical.launchAppIdConfirmed ||= candidate.launchAppIdConfirmed;

        if (!canonical.devtoolsSocket && candidate.devtoolsSocket) {
            canonical.devtoolsSocket = candidate.devtoolsSocket;
            canonical.attached = candidate.attached;
        } else if (
            candidate.devtoolsSocket &&
            candidate.devtoolsSocket !== canonical.devtoolsSocket
        ) {
            closeWebSocket(
                candidate.devtoolsSocket,
                1001,
                "alternate miniapp attachment superseded",
            );
        }

        debugSocketSessions.set(candidateSocket, canonical);
        candidate.debugSocket = undefined;
        candidate.devtoolsSocket = undefined;
        candidate.appService = undefined;
        candidate.attached = false;
        candidate.state = "closing";
        candidate.lastError = "promoted into canonical attachment";
        removeSession(candidate);
        touchSession(candidate);
        touchSession(canonical);
        startForegroundKeepAlive(canonical);
        startSessionHealthCheck(canonical);

        if (oldSocket && oldSocket !== candidateSocket) {
            debugSocketSessions.delete(oldSocket);
            closeWebSocket(
                oldSocket,
                1001,
                "superseded by a working miniapp attachment",
            );
        }
        if (
            oldDevtoolsSocket &&
            canonical.devtoolsSocket !== oldDevtoolsSocket
        ) {
            closeWebSocket(
                oldDevtoolsSocket,
                1001,
                "miniapp attachment changed",
            );
        }

        logger.info(
            `[miniapp] promoted successful attachment for ${appid}: ${candidate.traceId} -> ${canonical.traceId}`,
        );

        return canonical;
    };

    const bootstrapSession = async (session: MiniAppSession) => {
        const bootstrapStartedAt = Date.now();

        let bootstrapAttempt = 0;
        while (true) {
            bootstrapAttempt += 1;
            try {
                const appid = await resolveSessionAppId(session);
                if (session.closeInProgress) {
                    throw new Error("bootstrap cancelled by explicit close");
                }
                if (!session.launchId) {
                    const matchingPendingSpawn = pendingSpawns.get(appid);
                    if (
                        matchingPendingSpawn &&
                        matchingPendingSpawn.boundSessionId === undefined
                    ) {
                        bindPendingSpawn(session, matchingPendingSpawn);
                    }
                }
                const expectedAppId = session.requestedAppId;
                const launchMismatch =
                    expectedAppId !== undefined && expectedAppId !== appid;
                if (launchMismatch) {
                    const mismatchMessage =
                        `pending launch expected ${expectedAppId}, but the socket resolved to ${appid}`;
                    rejectPendingSpawn(
                        expectedAppId,
                        new Error(mismatchMessage),
                    );
                    session.windowHandle = undefined;
                    session.windowIdentity = undefined;
                    session.launchId = undefined;
                    session.launchStartedAt = undefined;
                    session.launchWindowCursor = undefined;
                    session.launchAppIdConfirmed = false;
                    logger.error(
                        `[miniapp] ${mismatchMessage}; HWND candidate discarded`,
                    );

                }
                if (appid) {
                    session.title = appid;
                    session.requestedAppId = appid;
                    rekeySessionByAppId(session, appid);
                }
                if (!launchMismatch) {
                    session.launchAppIdConfirmed = true;
                }
                captureWindowIdentity(session);
                session.state = "ready";
                session.lastError = undefined;
                startForegroundKeepAlive(session);
                startSessionHealthCheck(session);
                touchSession(session);
                if (appid && !launchMismatch) {
                    resolvePendingSpawn(appid, session);
                }
                logger.info(`[miniapp] miniapp ready: ${session.id}`);

                return;
            } catch (error) {
                const errorMessage = formatErrorMessage(error);
                const closeMessage = `miniapp bootstrap failed: ${errorMessage}`;
                if (session.closeInProgress) {
                    rejectSessionPendingSpawn(session, new Error(closeMessage));
                    logger.info(
                        `[miniapp] bootstrap stopped for ${session.id} because explicit close is in progress`,
                    );

                    return;
                }
                const socketAlive =
                    session.debugSocket?.readyState === WebSocket.OPEN;
                if (!socketAlive) {
                    // The miniapp disconnected while bootstrapping; the close
                    // handler already tore the session down. This is normal
                    // during rapid launch/reconnect cycles, not a failure.
                    logger.info(
                        `[miniapp] bootstrap interrupted for ${session.id}: ${errorMessage}`,
                    );
                    return;
                }
                if (
                    bootstrapAttempt <= BOOTSTRAP_MAX_RETRIES
                ) {
                    logger.info(
                        `[miniapp] bootstrap attempt ${bootstrapAttempt} failed for ${session.id}; retrying`,
                    );

                    await sleep(BOOTSTRAP_RETRY_INTERVAL_MS);
                    continue;
                }
                session.state = "closing";
                session.lastError = closeMessage;
                touchSession(session);
                stopForegroundKeepAlive(session);
                stopSessionHealthCheck(session);
                logger.error(
                    `[miniapp] bootstrap failed for ${session.id}:`,
                    error,
                );

                rejectSessionPendingSpawn(session, new Error(closeMessage));
                if (
                    session.debugSocket &&
                    session.debugSocket.readyState === WebSocket.OPEN
                ) {
                    logger.info(
                        `[miniapp] closing debug socket after failed bootstrap for ${session.id}`,
                    );
                    closeWebSocket(
                        session.debugSocket,
                        1011,
                        closeMessage,
                        true,
                    );
                }
                return;
            }
        }
    };

    const onCdpPayload = (session: MiniAppSession, payload: string) => {
        let parsed: any = null;
        try {
            parsed = JSON.parse(payload);
        } catch (error) {
            if (
                session.devtoolsSocket &&
                session.devtoolsSocket.readyState === WebSocket.OPEN
            ) {
                session.devtoolsSocket.send(payload);
            }
            return;
        }

        if (typeof parsed.id === "number") {
            const pending = session.pendingCommands.get(parsed.id);
            if (pending) {
                clearTimeout(pending.timeout);
                session.pendingCommands.delete(parsed.id);
                pending.resolve(parsed);
                return;
            }
        }

        if (
            parsed.method === "Runtime.executionContextCreated" &&
            typeof parsed.sessionId === "string"
        ) {
            const pendingContext = session.pendingContexts.get(parsed.sessionId);
            const frameId = parsed.params?.context?.auxData?.frameId;
            const contextId = parsed.params?.context?.id;
            if (
                pendingContext &&
                typeof contextId === "number" &&
                (
                    pendingContext.frameId === undefined ||
                    pendingContext.frameId === frameId
                )
            ) {
                clearTimeout(pendingContext.timeout);
                session.pendingContexts.delete(parsed.sessionId);
                pendingContext.resolve(contextId);
                return;
            }
        }

        if (
            session.appService &&
            typeof parsed.sessionId === "string" &&
            parsed.sessionId === session.appService.sessionId
        ) {
            return;
        }

        if (
            session.devtoolsSocket &&
            session.devtoolsSocket.readyState === WebSocket.OPEN
        ) {
            session.devtoolsSocket.send(payload);
        }
    };

    const onMiniAppMessage = (session: MiniAppSession, message: RawData) => {
        const buffer = rawDataToBuffer(message);
        session.lastMessageReceivedAt = Date.now();
        touchSession(session);
        logger.main_debug(
            `[miniapp] client received raw message (hex): ${bufferToHexString(buffer)}`,
        );
        let unwrappedData: any = null;
        try {
            const decodedData =
                messageProto.mmbizwxadevremote.WARemoteDebug_DebugMessage.decode(
                    buffer,
                );
            unwrappedData = codex.unwrapDebugMessageData(decodedData);
            logger.main_debug(`[miniapp] [DEBUG] decoded data:`);
            logger.main_debug(unwrappedData);
        } catch (error) {
            logger.error(`[miniapp] miniapp client err:`, error);
        }

        if (unwrappedData === null) {
            return;
        }

        if (unwrappedData.category === "chromeDevtoolsResult") {
            onCdpPayload(session, unwrappedData.data.payload);
        }
    };

    const closeVerifiedWindow = async (
        session: MiniAppSession,
        identity: MiniAppSession["windowIdentity"] & {},
    ) => {
        const closeStartedAt = Date.now();
        try {
            close_window(identity.handle, {
                pid: identity.pid,
                tid: identity.tid,
            });

        } catch (error) {

            throw error;
        }
        const deadline = Date.now() + INTERNAL_CDP_TIMEOUT_MS;
        while (Date.now() < deadline) {
            if (!is_window(identity.handle)) {

                return;
            }
            await sleep(MINIAPP_WINDOW_WAIT_INTERVAL_MS);
        }



        throw new Error(
            `miniapp window did not close: 0x${identity.handle.toString(16)}`,
        );
    };

    const closeViaMiniAppApi = async (session: MiniAppSession) => {
        const appService = session.appService;
        if (
            !appService ||
            !session.debugSocket ||
            session.debugSocket.readyState !== WebSocket.OPEN
        ) {
            return false;
        }

        try {
            const response = await sendInternalCommand(
                session,
                "Runtime.evaluate",
                {
                    expression: EXIT_MINIPROGRAM_EXPRESSION,
                    contextId: appService.contextId,
                    awaitPromise: true,
                    returnByValue: true,
                },
                appService.sessionId,
            );
            if (response.result?.result?.value !== "exit-requested") {
                return false;
            }
        } catch (error) {
            logger.main_debug(
                `[miniapp] exitMiniProgram unavailable for ${session.id}:`,
                error,
            );
            return false;
        }

        const deadline = Date.now() + CLOSE_CDP_GRACE_MS;
        while (Date.now() < deadline) {
            if (
                !session.debugSocket ||
                session.debugSocket.readyState !== WebSocket.OPEN
            ) {
                return true;
            }
            await sleep(MINIAPP_WINDOW_WAIT_INTERVAL_MS);
        }
        return false;
    };

    const closeViaCdp = async (session: MiniAppSession) => {
        const appService = session.appService;
        if (
            !appService ||
            !session.debugSocket ||
            session.debugSocket.readyState !== WebSocket.OPEN
        ) {
            return false;
        }

        try {
            await sendInternalCommand(session, "Target.closeTarget", {
                targetId: appService.targetId,
            });
        } catch (error) {
            logger.main_debug(
                `[miniapp] CDP closeTarget unavailable for ${session.id}:`,
                error,
            );
            return false;
        }

        const deadline = Date.now() + CLOSE_CDP_GRACE_MS;
        while (Date.now() < deadline) {
            if (
                !session.debugSocket ||
                session.debugSocket.readyState !== WebSocket.OPEN
            ) {
                return true;
            }
            await sleep(MINIAPP_WINDOW_WAIT_INTERVAL_MS);
        }
        return false;
    };

    const waitForWindowGone = async (
        handle: number,
        timeoutMs: number,
    ) => {
        const deadline = Date.now() + timeoutMs;
        while (Date.now() < deadline) {
            if (!is_window(handle)) {
                return true;
            }
            await sleep(MINIAPP_WINDOW_WAIT_INTERVAL_MS);
        }
        return false;
    };

    const closeKnownWindow = async (session: MiniAppSession) => {
        const identity = session.windowIdentity;
        const handle = session.windowHandle;
        if (
            identity &&
            (identity.launchId === session.launchId || !session.launchId)
        ) {
            const inspection = inspectWin32WindowIdentity(
                identity.handle,
                identity.pid,
            );
            if (inspection.windowExists && inspection.snapshot) {
                if (
                    identity.title &&
                    inspection.snapshot.title !== identity.title
                ) {
                    logger.info(
                        `[miniapp] refusing to close ${session.id}: window title changed ` +
                            `("${identity.title}" -> "${inspection.snapshot.title}"); ` +
                            `possible HWND reuse`,
                    );
                    return "failed" as const;
                }
                await closeVerifiedWindow(session, identity);
                return "closed" as const;
            }
            if (inspection.windowExists && !inspection.snapshot) {
                // The handle is alive; fall back to a pid/tid-guarded close so
                // a recycled or unrelated HWND is never targeted.
                close_window(identity.handle, {
                    pid: identity.pid,
                    tid: identity.tid,
                });
                const closed = await waitForWindowGone(
                    identity.handle,
                    INTERNAL_CDP_TIMEOUT_MS,
                );
                return closed ? "closed" : "failed";
            }
            return "gone" as const;
        }
        if (handle !== undefined) {
            if (!is_window(handle)) {
                return "gone" as const;
            }
            if (identity) {
                close_window(handle, {
                    pid: identity.pid,
                    tid: identity.tid,
                });
                const closed = await waitForWindowGone(
                    handle,
                    INTERNAL_CDP_TIMEOUT_MS,
                );
                return closed ? "closed" : "failed";
            }
        }
        return "unknown" as const;
    };

    const killMiniApp = async (
        session: MiniAppSession,
        reason: string,
    ) => {
        session.closeInProgress = true;
        session.state = "closing";
        session.lastError = reason;
        touchSession(session);
        stopForegroundKeepAlive(session);
        stopSessionHealthCheck(session);

        let windowOutcome: "closed" | "gone" | "unknown" | "failed" =
            "unknown";
        let closeError: string | null = null;

        // 1) Precise kill through the miniapp's own API while the socket is
        // still alive. This closes exactly the target miniapp with no window
        // guessing.
        if (session.debugSocket?.readyState === WebSocket.OPEN) {
            const exited = await closeViaMiniAppApi(session);
            if (exited) {
                windowOutcome = "closed";
                if (
                    session.windowHandle !== undefined &&
                    is_window(session.windowHandle)
                ) {
                    const gone = await waitForWindowGone(
                        session.windowHandle,
                        CLOSE_CDP_GRACE_MS,
                    );
                    if (!gone) {
                        windowOutcome = "failed";
                    }
                }
            }
        }

        // 2) Fall back to the captured window (pid/tid-guarded), then CDP.
        if (
            windowOutcome === "unknown" ||
            windowOutcome === "failed"
        ) {
            try {
                windowOutcome = await closeKnownWindow(session);
            } catch (error) {
                closeError = formatErrorMessage(error);
                windowOutcome = "failed";
                logger.error(
                    `[miniapp] window close failed for ${session.id}; continuing cleanup:`,
                    error,
                );
            }
        }
        try {
            if (
                (windowOutcome === "unknown" ||
                    windowOutcome === "failed") &&
                session.debugSocket?.readyState === WebSocket.OPEN
            ) {
                const cdpClosed = await closeViaCdp(session);
                if (cdpClosed) {
                    windowOutcome = "closed";
                }
            }
        } catch (error) {
            closeError = formatErrorMessage(error);
        }

        detachSession(session, reason);
        return {
            closed: windowOutcome === "closed" || windowOutcome === "gone",
            alreadyGone: windowOutcome === "gone",
            cleanupComplete: true,
            forced: false,
            launchCorrelatedClose: false,
            error: closeError,
        };
    };

    const retireStaleSession = async (
        session: MiniAppSession,
        options: { force?: boolean } = {},
    ) => {
        if (
            !options.force &&
            session.state === "ready" &&
            session.debugSocket?.readyState === WebSocket.OPEN &&
            session.appService !== undefined
        ) {
            return null;
        }

        const result = await killMiniApp(
            session,
            "stale session replaced by a new launch",
        );

        return result;
    };

    wss.on("connection", (ws: WebSocket) => {
        const session = createSession();
        session.debugSocket = ws;
        session.lastMessageReceivedAt = Date.now();
        sessions.set(session.id, session);
        debugSocketSessions.set(ws, session);
        logger.info(`[miniapp] miniapp client connected: ${session.id}`);

        ws.on("message", (message) => {
            const currentSession = debugSocketSessions.get(ws);
            if (currentSession) {
                onMiniAppMessage(currentSession, message);
            }
        });
        ws.on("error", (error) => {
            const currentSession = debugSocketSessions.get(ws);
            if (currentSession) {
                logger.error(
                    `[miniapp] miniapp client err (${currentSession.id}):`,
                    error,
                );
            } else {
                logger.error(`[miniapp] miniapp client err:`, error);
            }
        });
        ws.on("close", (code, reason) => {
            const currentSession = debugSocketSessions.get(ws);
            if (!currentSession) {
                return;
            }

            const disconnectError = new Error("miniapp disconnected");
            rejectSessionPendingSpawn(currentSession, disconnectError);
            const retainedForExplicitClose = teardownSession(
                currentSession,
                disconnectError.message,
            );
            debugSocketSessions.delete(ws);
            logger.info(
                retainedForExplicitClose
                    ? `[miniapp] miniapp client disconnected: ${currentSession.id}; retaining cached hwnd for explicit close`
                    : `[miniapp] miniapp client disconnected: ${currentSession.id}`,
            );

        });

        void bootstrapSession(session).finally(() => {
            captureWindowIdentity(session);
        });
    });

    return {
        listDebuggableSessions,
        killMiniApp,
        retireStaleSession,
        evaluateInAppContext,
        promoteSessionAttachment,
        retainPendingLaunchWindow,
        sendMiniAppCdpMessage,
    };
};
