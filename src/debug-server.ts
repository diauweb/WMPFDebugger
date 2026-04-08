import WebSocket, { RawData, WebSocketServer } from "ws";

import { CliOptions } from "./cli";
import { Logger } from "./logger";
import {
    MiniAppSession,
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

export const debug_server = (
    options: CliOptions,
    logger: Logger,
    sessions: Map<string, MiniAppSession>,
    pendingSpawns: Map<string, PendingSpawn>,
) => {
    const debugSocketSessions = new Map<WebSocket, MiniAppSession>();
    const wss = new WebSocketServer({ port: options.debugPort });
    logger.info(
        `[server] debug server running on ws://localhost:${options.debugPort}`,
    );
    logger.info(`[server] debug server waiting for miniapp to connect...`);

    const listDebuggableSessions = () =>
        Array.from(sessions.values()).filter(
            (session) => session.debugSocket !== undefined,
        );

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

    const removeSession = (session: MiniAppSession) => {
        const currentSession = sessions.get(session.id);
        if (currentSession === session) {
            sessions.delete(session.id);
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

            const attachResponse = await sendInternalCommand(
                session,
                "Target.attachToTarget",
                {
                    targetId: targetInfo.targetId,
                    flatten: true,
                },
            );
            appServiceSessionId = attachResponse.result?.sessionId;
            if (typeof appServiceSessionId !== "string") {
                throw new Error("unable to attach app target");
            }
            targetId = targetInfo.targetId;
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

        session.appService = {
            targetId,
            sessionId: appServiceSessionId,
            frameId,
            contextId,
        };
        touchSession(session);
        return session.appService;
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
            typeof appId === "string" && appId.length > 0 ? appId : "";
        session.title = appidValue || session.title;
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
                rekeySessionByAppId(session, appid);
                resolvePendingSpawn(appid, session);
            }
            touchSession(session);
            logger.info(`[miniapp] miniapp ready: ${session.id}`);
        } catch (error) {
            touchSession(session);
            logger.error(`[miniapp] bootstrap failed for ${session.id}:`, error);
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
        if (!session.debugSocket || !session.appService) {
            throw new Error("miniapp session is not ready for close");
        }

        await sendInternalCommand(session, "Target.closeTarget", {
            targetId: session.appService.targetId,
        });
        await waitForMiniAppClose(session);
    };

    wss.on("connection", (ws: WebSocket) => {
        const session = createSession();
        session.debugSocket = ws;
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
        ws.on("close", () => {
            const currentSession = debugSocketSessions.get(ws);
            if (!currentSession) {
                return;
            }

            currentSession.debugSocket = undefined;
            currentSession.appService = undefined;
            currentSession.attached = false;
            touchSession(currentSession);
            rejectPendingWork(currentSession, "miniapp disconnected");
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
        evaluateInAppContext,
        sendMiniAppCdpMessage,
    };
};
