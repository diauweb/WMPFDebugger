import WebSocket, { RawData } from "ws";

import { Logger } from "./logger";
import {
    AppServiceBinding,
    CdpFrameTree,
    INTERNAL_CDP_TIMEOUT_MS,
    MiniAppSession,
    PendingContext,
    bufferToHexString,
    flattenFrameTree,
    rawDataToBuffer,
    touchSession,
} from "./session";

const codex = require("./third-party/RemoteDebugCodex.js");
const messageProto = require("./third-party/WARemoteDebugProtobuf.js");
const FOREGROUND_KEEP_ALIVE_MS = 3_000;

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

export const isRecoverableAppContextError = (error: unknown) => {
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

export const formatErrorMessage = (error: unknown) =>
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

export const createMiniAppCdpRuntime = (logger: Logger) => {
    const foregroundKeepAliveActive = new WeakSet<MiniAppSession>();
    const disabledForegroundCommands = new WeakMap<MiniAppSession, Set<string>>();

    const sendMiniAppCdpMessage = (session: MiniAppSession, message: string) => {
        if (
            !session.debugSocket ||
            session.debugSocket.readyState !== WebSocket.OPEN
        ) {
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
    ) => {
        const previous = session.pendingContexts.get(sessionId);
        if (previous) {
            clearTimeout(previous.timeout);
            session.pendingContexts.delete(sessionId);
            previous.reject(new Error("execution context wait replaced"));
        }

        return new Promise<number>((resolve, reject) => {
            let pendingContext: PendingContext;
            const timeout = setTimeout(() => {
                if (session.pendingContexts.get(sessionId) !== pendingContext) {
                    return;
                }
                session.pendingContexts.delete(sessionId);
                reject(new Error("execution context timeout"));
            }, INTERNAL_CDP_TIMEOUT_MS);
            pendingContext = {
                frameId,
                resolve,
                reject,
                timeout,
            };
            session.pendingContexts.set(sessionId, pendingContext);
        });
    };

    const cancelExecutionContextWait = (
        session: MiniAppSession,
        sessionId: string,
        error: unknown,
    ) => {
        const pendingContext = session.pendingContexts.get(sessionId);
        if (!pendingContext) {
            return;
        }
        clearTimeout(pendingContext.timeout);
        session.pendingContexts.delete(sessionId);
        pendingContext.reject(
            error instanceof Error ? error : new Error(formatErrorMessage(error)),
        );
    };

    const findAppTargetId = async (
        session: MiniAppSession,
    ): Promise<string> => {
        const targetResponse = await sendInternalCommand(
            session,
            "Target.getTargets",
        );
        const targetInfos = targetResponse.result?.targetInfos || [];
        const targetCandidates = targetInfos.filter(
            (candidate: any) => String(candidate.title || "") === "AppIndex",
        );
        const targetInfo = targetCandidates[targetCandidates.length - 1];
        if (!targetInfo || typeof targetInfo.targetId !== "string") {
            const observedTitles = targetInfos
                .map((candidate: any) => String(candidate.title || "<untitled>"))
                .join(", ");
            throw new Error(
                `unable to find app target (observed: ${observedTitles || "none"})`,
            );
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
        if (options?.forceAttach) {
            session.appService = undefined;
            session.appServiceBootstrap = undefined;
        }
        const existingBinding =
            session.appService ?? session.appServiceBootstrap;
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
            session.appServiceBootstrap = {
                targetId,
                sessionId: appServiceSessionId,
            };
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
            session.appServiceBootstrap = {
                targetId,
                sessionId: appServiceSessionId,
                frameId,
            };
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
            contextPromise.catch(() => undefined);
            try {
                await sendInternalCommand(
                    session,
                    "Runtime.enable",
                    {},
                    appServiceSessionId,
                );
                contextId = await contextPromise;
            } catch (error) {
                cancelExecutionContextWait(session, appServiceSessionId, error);
                await contextPromise.catch(() => undefined);
                throw error;
            }
        }

        const appService = {
            targetId,
            sessionId: appServiceSessionId,
            frameId,
            contextId,
        };
        session.appService = appService;
        session.appServiceBootstrap = undefined;
        if (session.state === "closing") {
            throw new Error("app context became unavailable");
        }
        touchSession(session);
        return appService;
    };

    const resolveSessionAppId = async (session: MiniAppSession) => {
        const appContext = await discoverAppContext(session);
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

    return {
        applyForegroundState,
        evaluateInAppContext,
        onMiniAppMessage,
        resolveSessionAppId,
        sendMiniAppCdpMessage,
        startForegroundKeepAlive,
    };
};
