import WebSocket, { RawData, WebSocketServer } from "ws";

import { CliOptions } from "./cli";
import type { FridaServerHandle } from "./frida-server";
import { Logger } from "./logger";
import { report_fatal_error } from "./process-guards";
import { close_window } from "./wechat-host";
import {
    MiniAppSession,
    AppServiceBinding,
    PendingSpawn,
    CdpFrameTree,
    CloseWaiter,
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
const MINIAPP_WINDOW_CLAIM_GRACE_MS = 1_000;
const MINIAPP_WINDOW_WAIT_MS = 2_000;
const MINIAPP_WINDOW_WAIT_INTERVAL_MS = 100;

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
    fridaServer: Pick<FridaServerHandle, "claimMiniAppWindow">,
) => {
    const debugSocketSessions = new Map<WebSocket, MiniAppSession>();
    const foregroundKeepAliveActive = new WeakSet<MiniAppSession>();
    const disabledForegroundCommands = new WeakMap<MiniAppSession, Set<string>>();
    const wss = new WebSocketServer({ port: options.debugPort });
    wss.on("error", (error) => {
        report_fatal_error(logger, "[server] debug server error", error);
    });
    logger.info(
        `[server] debug server running on ws://localhost:${options.debugPort}`,
    );
    logger.info(`[server] debug server waiting for miniapp to connect...`);

    const listDebuggableSessions = () =>
        Array.from(sessions.values()).filter(
            (session) =>
                session.state === "ready" &&
                session.debugSocket !== undefined &&
                session.appService !== undefined,
        );

    const findPendingSpawnHint = () => {
        const pendingSpawnList = Array.from(pendingSpawns.values()).sort(
            (left, right) => left.createdAt - right.createdAt,
        );
        return pendingSpawnList.length === 1 ? pendingSpawnList[0] : undefined;
    };

    const applyPendingSpawnHint = (session: MiniAppSession) => {
        const pendingSpawn = findPendingSpawnHint();
        if (!pendingSpawn) {
            return;
        }

        session.requestedAppId = pendingSpawn.appid;
        session.launchStartedAt = pendingSpawn.createdAt;
        session.title = pendingSpawn.appid;
        logger.info(
            `[miniapp] linked pending spawn ${pendingSpawn.appid} to ${session.id}`,
        );
    };

    const resolvePendingSpawn = (appid: string, session: MiniAppSession) => {
        const pendingSpawn = pendingSpawns.get(appid);
        if (!pendingSpawn) {
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
        if (session.requestedAppId) {
            rejectPendingSpawn(session.requestedAppId, error);
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

    const resolveCloseWaiters = (session: MiniAppSession) => {
        for (const waiter of session.closeWaiters) {
            clearTimeout(waiter.timeout);
            waiter.resolve();
        }
        session.closeWaiters.clear();
    };

    const stopForegroundKeepAlive = (session: MiniAppSession) => {
        if (session.foregroundKeepAlive) {
            clearInterval(session.foregroundKeepAlive);
            session.foregroundKeepAlive = undefined;
        }
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
        rejectPendingWork(session, reason);
        resolveCloseWaiters(session);
        removeSession(session);

        if (debugSocket) {
            debugSocketSessions.delete(debugSocket);
        }

        closeWebSocket(devtoolsSocket, 1001, reason);
        closeWebSocket(debugSocket, 1011, reason, true);
    };

    const rememberMiniAppWindow = (
        session: MiniAppSession,
        options?: { fallbackToLatest?: boolean },
    ) => {
        if (session.windowHandle !== undefined) {
            return session.windowHandle;
        }

        try {
            const claimBaseline = session.launchStartedAt ?? session.createdAt;
            const miniAppWindow = fridaServer.claimMiniAppWindow({
                createdAfter: claimBaseline,
                graceMs: MINIAPP_WINDOW_CLAIM_GRACE_MS,
                fallbackToLatest: options?.fallbackToLatest ?? false,
            });
            if (miniAppWindow !== undefined) {
                session.windowHandle = miniAppWindow.handle;
                logger.info(
                    `[miniapp] remembered window hwnd for ${session.id}: 0x${miniAppWindow.handle.toString(16)}`,
                );
            }
        } catch (error) {
            logger.error(
                `[miniapp] failed to remember window hwnd for ${session.id}:`,
                error,
            );
        }

        return session.windowHandle;
    };

    const sleep = (ms: number) =>
        new Promise<void>((resolve) => setTimeout(resolve, ms));

    const waitForMiniAppWindow = async (session: MiniAppSession) => {
        const deadline = Date.now() + MINIAPP_WINDOW_WAIT_MS;
        while (Date.now() < deadline) {
            const windowHandle = rememberMiniAppWindow(session);
            if (windowHandle !== undefined) {
                return windowHandle;
            }
            if (
                !session.debugSocket ||
                session.debugSocket.readyState !== WebSocket.OPEN
            ) {
                return undefined;
            }
            await sleep(MINIAPP_WINDOW_WAIT_INTERVAL_MS);
        }

        return rememberMiniAppWindow(session, { fallbackToLatest: true });
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

            void applyForegroundState(session, appService);
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
            const contextPromise = waitForExecutionContext(
                session,
                appServiceSessionId,
                frameId,
            );
            await sendInternalCommand(
                session,
                "Runtime.enable",
                {},
                appServiceSessionId,
            );
            contextId = await contextPromise;
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
        logger.info(
            "[miniapp] account info:",
            accountInfoResponse.result?.result?.value ?? null,
        );
        const accountInfoValue = accountInfoResponse.result?.result?.value;
        const appId = accountInfoValue?.miniProgram?.appId;
        const appidValue =
            typeof appId === "string" && appId.trim().length > 0
                ? appId.trim()
                : "";
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
            return await sendEvaluate(false);
        } catch (error) {
            if (!isRecoverableAppContextError(error)) {
                throw error;
            }

            logger.info(
                `[miniapp] refreshing appContext for ${session.id} after evaluate failure`,
            );
            return sendEvaluate(true);
        }
    };

    const rekeySessionByAppId = (session: MiniAppSession, appid: string) => {
        if (session.id === appid) {
            if (!sessions.has(appid)) {
                sessions.set(appid, session);
            }
            return;
        }

        const existing = sessions.get(appid);
        if (existing && existing !== session) {
            logger.error(
                `[miniapp] duplicate live session for ${appid}: ${existing.id} and ${session.id}`,
            );
            return;
        }

        const previousId = session.id;
        sessions.delete(previousId);
        session.id = appid;
        sessions.set(appid, session);
    };

    const bootstrapSession = async (session: MiniAppSession) => {
        try {
            const appid = await resolveSessionAppId(session);
            if (appid) {
                session.title = appid;
                session.requestedAppId = appid;
                rekeySessionByAppId(session, appid);
            }
            session.state = "ready";
            session.lastError = undefined;
            startForegroundKeepAlive(session);
            touchSession(session);
            if (appid) {
                resolvePendingSpawn(appid, session);
            }
            logger.info(`[miniapp] miniapp ready: ${session.id}`);
        } catch (error) {
            const errorMessage = formatErrorMessage(error);
            const closeMessage = `miniapp bootstrap failed: ${errorMessage}`;
            session.lastError = closeMessage;
            touchSession(session);
            logger.error(`[miniapp] bootstrap failed for ${session.id}:`, error);
            rejectSessionPendingSpawn(session, new Error(closeMessage));
            await killMiniApp(session, closeMessage);
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

    const waitForMiniAppClose = (session: MiniAppSession) =>
        new Promise<void>((resolve, reject) => {
            if (!session.debugSocket) {
                resolve();
                return;
            }

            const timeout = setTimeout(() => {
                session.closeWaiters.delete(waiter);
                reject(new Error("miniapp close timeout"));
            }, INTERNAL_CDP_TIMEOUT_MS);
            const waiter: CloseWaiter = {
                resolve: () => {
                    resolve();
                },
                timeout,
            };
            session.closeWaiters.add(waiter);
        });

    const closeMiniApp = async (session: MiniAppSession) => {
        if (!session.debugSocket) {
            throw new Error("miniapp debug socket unavailable for close");
        }

        const windowHandle = await waitForMiniAppWindow(session);
        if (windowHandle === undefined) {
            throw new Error("miniapp window handle unavailable for close");
        }

        const closePromise = waitForMiniAppClose(session);
        try {
            close_window(windowHandle);
        } catch (error) {
            if (!session.debugSocket) {
                await closePromise.catch(() => undefined);
                return;
            }
            closePromise.catch(() => undefined);
            throw error;
        }
        await closePromise;
    };

    const killMiniApp = async (session: MiniAppSession, reason: string) => {
        session.state = "closing";
        session.lastError = reason;
        touchSession(session);
        stopForegroundKeepAlive(session);

        if (!session.debugSocket) {
            detachSession(session, reason);
            logger.info(
                `[miniapp] miniapp session detached after debug socket closed: ${session.id}`,
            );
            return {
                closed: false,
                forced: true,
            };
        }

        try {
            await closeMiniApp(session);
            return {
                closed: true,
                forced: false,
            };
        } catch (error) {
            logger.error(
                `[miniapp] window close failed for ${session.id}; keeping session attached for retry:`,
                error,
            );
            session.lastError = `miniapp close failed: ${formatErrorMessage(error)}`;
            touchSession(session);
            return {
                closed: false,
                forced: false,
            };
        }
    };

    wss.on("connection", (ws: WebSocket) => {
        const session = createSession();
        applyPendingSpawnHint(session);
        session.debugSocket = ws;
        sessions.set(session.id, session);
        debugSocketSessions.set(ws, session);
        rememberMiniAppWindow(session);
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
        ws.on("close", () => {
            const currentSession = debugSocketSessions.get(ws);
            if (!currentSession) {
                return;
            }

            currentSession.debugSocket = undefined;
            currentSession.appService = undefined;
            currentSession.attached = false;
            currentSession.state = "closing";
            touchSession(currentSession);
            stopForegroundKeepAlive(currentSession);
            const disconnectError = new Error("miniapp disconnected");
            rejectSessionPendingSpawn(currentSession, disconnectError);
            rejectPendingWork(currentSession, disconnectError.message);
            resolveCloseWaiters(currentSession);
            if (
                currentSession.devtoolsSocket &&
                currentSession.devtoolsSocket.readyState === WebSocket.OPEN
            ) {
                currentSession.devtoolsSocket.close();
            }
            removeSession(currentSession);
            debugSocketSessions.delete(ws);
            logger.info(
                `[miniapp] miniapp client disconnected: ${currentSession.id}`,
            );
        });

        void bootstrapSession(session);
    });

    return {
        listDebuggableSessions,
        closeMiniApp,
        killMiniApp,
        evaluateInAppContext,
        sendMiniAppCdpMessage,
    };
};
