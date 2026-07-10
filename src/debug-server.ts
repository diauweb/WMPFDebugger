import WebSocket, { WebSocketServer } from "ws";

import { CliOptions } from "./cli";
import { DebugSessionLifecycle } from "./debug-session-lifecycle";
import type { FridaServerHandle } from "./frida-server";
import {
    LaunchAttempt,
    MiniAppLaunchError,
    MiniAppLaunchCoordinator,
} from "./launch-coordinator";
import { Logger } from "./logger";
import {
    createMiniAppCdpRuntime,
    formatErrorMessage,
    isRecoverableAppContextError,
} from "./miniapp-cdp-runtime";
import { MiniAppWindowLifecycle } from "./miniapp-window-lifecycle";
import { report_fatal_error } from "./process-guards";
import {
    MiniAppSession,
    MAX_MINIAPP_LAUNCH_DISPATCHES,
    MINIAPP_BOOTSTRAP_TIMEOUT_MS,
    touchSession,
    createSession,
} from "./session";
import { MiniAppSessionRegistry } from "./session-registry";

const MINIAPP_BOOTSTRAP_RETRY_MS = 250;

export const debug_server = (
    options: CliOptions,
    logger: Logger,
    sessionRegistry: MiniAppSessionRegistry,
    launches: MiniAppLaunchCoordinator,
    fridaServer: Pick<FridaServerHandle, "claimMiniAppWindow">,
) => {
    const sessionLifecycle = new DebugSessionLifecycle(
        logger,
        sessionRegistry,
    );
    const windowLifecycle = new MiniAppWindowLifecycle(
        logger,
        launches,
        fridaServer,
        sessionLifecycle,
    );
    const cdpRuntime = createMiniAppCdpRuntime(logger);
    const wss = new WebSocketServer({ port: options.debugPort });
    wss.on("error", (error) => {
        report_fatal_error(logger, "[server] debug server error", error);
    });
    logger.info(
        `[server] debug server running on ws://localhost:${options.debugPort}`,
    );
    logger.info(`[server] debug server waiting for miniapp to connect...`);

    const listDebuggableSessions = () => sessionRegistry.listDebuggable();

    const sleep = (ms: number) =>
        new Promise<void>((resolve) => setTimeout(resolve, ms));

    const rekeySessionByAppId = async (
        session: MiniAppSession,
        appid: string,
    ) => {
        const existing = sessionRegistry.getExact(appid);
        if (existing === session) {
            return;
        }
        if (existing && existing !== session) {
            const launchAttempt = launches.getSessionAttempt(session);
            if (!launchAttempt) {
                throw new Error(
                    `duplicate live session for ${appid}: keeping ${existing.id}`,
                );
            }
            launches.addCleanupSession(launchAttempt, existing);
            const closeResult = await windowLifecycle.kill(
                existing,
                `replacing duplicate session for launch ${launchAttempt.id}`,
            );
            if (!closeResult.closed && !closeResult.forced) {
                throw new Error(
                    `duplicate session ${existing.id} could not be closed`,
                );
            }
            launches.completeCleanupSession(launchAttempt, existing);
        }

        sessionRegistry.rekey(session, appid);
    };

    const resolveSessionAppIdWithRetry = async (session: MiniAppSession) => {
        const deadline = Date.now() + MINIAPP_BOOTSTRAP_TIMEOUT_MS;
        let attemptNumber = 0;
        let lastError: unknown;

        while (
            session.state === "bootstrapping" &&
            session.debugSocket?.readyState === WebSocket.OPEN
        ) {
            attemptNumber += 1;
            try {
                return await cdpRuntime.resolveSessionAppId(session);
            } catch (error) {
                lastError = error;
                if (isRecoverableAppContextError(error)) {
                    session.appService = undefined;
                    session.appServiceBootstrap = undefined;
                }
                const remaining = deadline - Date.now();
                if (
                    (session as MiniAppSession).state === "closing" ||
                    remaining <= 0
                ) {
                    break;
                }
                logger.info(
                    `[miniapp] bootstrap attempt ${attemptNumber} pending for ${session.id}: ${formatErrorMessage(error)}`,
                );
                await sleep(Math.min(MINIAPP_BOOTSTRAP_RETRY_MS, remaining));
            }
        }

        if (session.state === "closing") {
            throw new Error("miniapp bootstrap was cancelled");
        }
        if (session.debugSocket?.readyState !== WebSocket.OPEN) {
            throw new Error("miniapp disconnected during bootstrap");
        }
        throw lastError instanceof Error
            ? lastError
            : new Error("miniapp bootstrap timed out");
    };

    const bootstrapSession = async (session: MiniAppSession) => {
        try {
            const appid = await resolveSessionAppIdWithRetry(session);
            const requestedAppId = session.requestedAppId;
            let launchAttempt = launches.getSessionAttempt(session);
            let displacedSession: MiniAppSession | undefined;
            if (
                launchAttempt &&
                requestedAppId &&
                requestedAppId !== appid
            ) {
                const mismatchedAttempt = launchAttempt;
                const mismatchMessage =
                    `launch ${mismatchedAttempt.id} expected ${requestedAppId}, ` +
                    `but connection resolved to ${appid}`;
                logger.error(
                    `[miniapp] ${mismatchMessage}; closing the mismatched singleton`,
                );
                launches.releaseMismatchedSession(
                    mismatchedAttempt,
                    session,
                );
                const closeResult = await windowLifecycle.kill(
                    session,
                    mismatchMessage,
                );
                if (closeResult.closed || closeResult.forced) {
                    const lateSession =
                        mismatchedAttempt.lateResolvedSession;
                    const completion =
                        launches.completeMismatchedSessionCleanup(
                            mismatchedAttempt,
                            session,
                        );
                    if (!completion || completion === "resolved") {
                        return;
                    }
                    if (completion === "adopted" && lateSession) {
                        launches.setPhase(
                            mismatchedAttempt,
                            "bootstrapping",
                            MINIAPP_BOOTSTRAP_TIMEOUT_MS,
                            (expiredAttempt) => {
                                const message = `matching miniapp connection did not finish bootstrap (launch ${expiredAttempt.id})`;
                                void launches.fail(
                                    expiredAttempt,
                                    new MiniAppLaunchError(message, 504),
                                    async () => {
                                        const cleanupResult =
                                            await windowLifecycle.cleanupLaunchAttempt(
                                                expiredAttempt,
                                                message,
                                            );
                                        return (
                                            cleanupResult.closed ||
                                            cleanupResult.forced
                                        );
                                    },
                                );
                            },
                        );
                        return;
                    }
                    if (
                        (mismatchedAttempt.dispatchCount ?? 0) >=
                        MAX_MINIAPP_LAUNCH_DISPATCHES
                    ) {
                        await launches.fail(
                            mismatchedAttempt,
                            new MiniAppLaunchError(
                                `miniapp launch repeatedly connected to the wrong runtime (${mismatchMessage})`,
                                502,
                            ),
                            async () => true,
                        );
                        return;
                    }
                    try {
                        if (!mismatchedAttempt.redispatch) {
                            throw new Error(
                                "miniapp launch redispatch is unavailable",
                            );
                        }
                        await mismatchedAttempt.redispatch();
                    } catch (error) {
                        const redispatchError =
                            error instanceof Error
                                ? error
                                : new Error("miniapp redispatch failed");
                        await launches.fail(
                            mismatchedAttempt,
                            redispatchError,
                            async () => {
                                const cleanupResult =
                                    await windowLifecycle.cleanupLaunchAttempt(
                                        mismatchedAttempt,
                                        redispatchError.message,
                                    );
                                return (
                                    cleanupResult.closed ||
                                    cleanupResult.forced
                                );
                            },
                        );
                    }
                } else {
                    await launches.fail(
                        mismatchedAttempt,
                        new MiniAppLaunchError(
                            `${mismatchMessage}; mismatched miniapp could not be closed`,
                            409,
                        ),
                        async () => {
                            const retryResult = await windowLifecycle.cleanupLaunchAttempt(
                                mismatchedAttempt,
                                mismatchMessage,
                            );
                            return retryResult.closed || retryResult.forced;
                        },
                    );
                }
                return;
            } else if (
                session.launchAttemptId !== undefined &&
                !launchAttempt
            ) {
                const blockedAttempt = requestedAppId
                    ? launches.get(requestedAppId)
                    : undefined;
                if (
                    blockedAttempt?.phase === "blocked" &&
                    blockedAttempt.id === session.launchAttemptId &&
                    blockedAttempt.appid === appid
                ) {
                    const adopted = launches.adoptResolvedSession(
                        session,
                        appid,
                    );
                    launchAttempt = adopted?.attempt;
                    displacedSession = adopted?.displacedSession;
                }
                if (!launchAttempt) {
                    throw new Error(
                        "miniapp launch attempt expired during bootstrap",
                    );
                }
            }

            if (!launchAttempt) {
                const adopted = launches.adoptResolvedSession(session, appid);
                launchAttempt = adopted?.attempt;
                displacedSession = adopted?.displacedSession;
                if (launchAttempt) {
                    logger.info(
                        `[miniapp] launch ${launchAttempt.id} adopted the matching ${appid} connection after identity validation`,
                    );
                }
            }

            session.title = appid;
            session.resolvedAppId = appid;
            if (displacedSession && displacedSession !== session) {
                const closeResult = await windowLifecycle.kill(
                    displacedSession,
                    `replacing mismatched session for launch ${launchAttempt?.id ?? "unknown"}`,
                );
                if (!closeResult.closed && !closeResult.forced) {
                    if (launchAttempt) {
                        const cleanupAttempt = launchAttempt;
                        const message = `displaced session ${displacedSession.id} could not be closed`;
                        await launches.fail(
                            cleanupAttempt,
                            new MiniAppLaunchError(message, 409),
                            async () => {
                                const cleanupResult =
                                    await windowLifecycle.cleanupLaunchAttempt(
                                        cleanupAttempt,
                                        message,
                                    );
                                return (
                                    cleanupResult.closed ||
                                    cleanupResult.forced
                                );
                            },
                        );
                        return;
                    }
                    throw new Error(
                        `displaced session ${displacedSession.id} could not be closed`,
                    );
                }
                if (launchAttempt) {
                    launches.completeCleanupSession(
                        launchAttempt,
                        displacedSession,
                    );
                }
            }
            await rekeySessionByAppId(session, appid);
            launchAttempt ??= launches.getSessionAttempt(session);
            if (!launchAttempt) {
                const finalAdoption = launches.adoptResolvedSession(
                    session,
                    appid,
                );
                launchAttempt = finalAdoption?.attempt;
                const finalDisplaced = finalAdoption?.displacedSession;
                if (finalDisplaced && finalDisplaced !== session) {
                    const finalClose = await windowLifecycle.kill(
                        finalDisplaced,
                        `reconciling late session for launch ${launchAttempt?.id ?? "unknown"}`,
                    );
                    if (!finalClose.closed && !finalClose.forced) {
                        if (launchAttempt) {
                            const cleanupAttempt = launchAttempt;
                            const message = `late displaced session ${finalDisplaced.id} could not be closed`;
                            await launches.fail(
                                cleanupAttempt,
                                new MiniAppLaunchError(message, 409),
                                async () => {
                                    const cleanupResult =
                                        await windowLifecycle.cleanupLaunchAttempt(
                                            cleanupAttempt,
                                            message,
                                        );
                                    return (
                                        cleanupResult.closed ||
                                        cleanupResult.forced
                                    );
                                },
                            );
                            return;
                        }
                        throw new Error(
                            `late displaced session ${finalDisplaced.id} could not be closed`,
                        );
                    }
                    if (launchAttempt) {
                        launches.completeCleanupSession(
                            launchAttempt,
                            finalDisplaced,
                        );
                    }
                }
                launchAttempt ??= launches.getSessionAttempt(session);
            }
            if (session.state !== "bootstrapping") {
                throw new Error("miniapp bootstrap was cancelled before ready");
            }
            if (
                launchAttempt &&
                (launchAttempt.phase === "cleaning" ||
                    launchAttempt.phase === "cleaning-mismatch" ||
                    launchAttempt.phase === "blocked" ||
                    launches.getSessionAttempt(session) !== launchAttempt)
            ) {
                throw new Error(
                    "miniapp launch stopped before bootstrap completed",
                );
            }
            session.state = "ready";
            session.lastError = undefined;
            if (!launchAttempt) {
                launches.recordLateResolvedSession(session, appid);
            }
            if (launches.isCleanupSession(session)) {
                session.state = "closing";
                session.lastError =
                    "miniapp is quarantined until prior launch cleanup completes";
                touchSession(session);
                return;
            }
            cdpRuntime.startForegroundKeepAlive(session);
            touchSession(session);
            if (launchAttempt && !launches.resolve(launchAttempt, session)) {
                throw new Error("miniapp became ready after its launch expired");
            }
            logger.info(
                `[miniapp] miniapp ready: ${session.id}` +
                    (launchAttempt ? ` (launch ${launchAttempt.id})` : ""),
            );
            const appService = session.appService;
            if (appService) {
                void cdpRuntime
                    .applyForegroundState(session, appService)
                    .catch((error) => {
                        logger.main_debug(
                            `[miniapp] initial foreground state failed (${session.id}):`,
                            error,
                        );
                    });
            }
        } catch (error) {
            const errorMessage = formatErrorMessage(error);
            const closeMessage = `miniapp bootstrap failed: ${errorMessage}`;
            session.lastError = closeMessage;
            touchSession(session);
            logger.error(`[miniapp] bootstrap failed for ${session.id}:`, error);
            const launchAttempt = launches.getSessionAttempt(session);
            if (launchAttempt) {
                await launches.fail(
                    launchAttempt,
                    new Error(closeMessage),
                    async () => {
                        const cleanupResult = await windowLifecycle.cleanupLaunchAttempt(
                            launchAttempt,
                            closeMessage,
                        );
                        return cleanupResult.closed || cleanupResult.forced;
                    },
                );
            } else {
                await windowLifecycle.kill(session, closeMessage);
            }
        }
    };

    wss.on("connection", (ws: WebSocket) => {
        const session = createSession();
        session.debugSocket = ws;
        const launchAttempt = launches.claimActiveSession(session);
        const cancellationAttempt = launchAttempt
            ? undefined
            : launches.trackCancelledSession(session);
        if (launchAttempt) {
            session.title = launchAttempt.appid;
            logger.info(
                `[miniapp] launch ${launchAttempt.id} claimed connection for ${launchAttempt.appid}`,
            );
        } else if (cancellationAttempt) {
            logger.info(
                `[miniapp] launch ${cancellationAttempt.id} quarantined a connection that arrived during cancellation`,
            );
        }
        sessionRegistry.add(session);
        sessionLifecycle.registerSocket(ws, session);
        windowLifecycle.rememberWindow(session);
        logger.info(`[miniapp] miniapp client connected: ${session.id}`);

        if (launchAttempt) {
            launches.setPhase(
                launchAttempt,
                "bootstrapping",
                MINIAPP_BOOTSTRAP_TIMEOUT_MS,
                (expiredAttempt) => {
                    const message = `miniapp bootstrap timed out for ${expiredAttempt.appid} (launch ${expiredAttempt.id})`;
                    logger.error(`[miniapp] ${message}`);
                    void launches.fail(
                        expiredAttempt,
                        new MiniAppLaunchError(message, 504),
                        async () => {
                            const cleanupResult =
                                await windowLifecycle.cleanupLaunchAttempt(
                                expiredAttempt,
                                message,
                            );
                            return cleanupResult.closed || cleanupResult.forced;
                        },
                    );
                },
            );
        }

        ws.on("message", (message) => {
            const currentSession = sessionLifecycle.getBySocket(ws);
            if (currentSession) {
                cdpRuntime.onMiniAppMessage(currentSession, message);
            }
        });
        ws.on("error", (error) => {
            const currentSession = sessionLifecycle.getBySocket(ws);
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
            const currentSession = sessionLifecycle.getBySocket(ws);
            if (!currentSession) {
                return;
            }

            currentSession.debugSocket = undefined;
            currentSession.appService = undefined;
            currentSession.appServiceBootstrap = undefined;
            currentSession.attached = false;
            currentSession.state = "closing";
            touchSession(currentSession);
            sessionLifecycle.stopForegroundKeepAlive(currentSession);
            const disconnectError = new MiniAppLaunchError(
                "miniapp disconnected during launch",
                502,
            );
            const currentAttempt = launches.getSessionAttempt(currentSession);
            if (currentAttempt) {
                void launches.fail(
                    currentAttempt,
                    disconnectError,
                    async () => {
                        const cleanupResult =
                            await windowLifecycle.cleanupLaunchAttempt(
                            currentAttempt,
                            disconnectError.message,
                        );
                        return cleanupResult.closed || cleanupResult.forced;
                    },
                );
            } else {
                void windowLifecycle.kill(
                    currentSession,
                    "miniapp debug socket disconnected",
                ).catch((error) => {
                    logger.error(
                        `[miniapp] disconnected session cleanup failed (${currentSession.id}):`,
                        error,
                    );
                });
            }
            sessionLifecycle.rejectPendingWork(
                currentSession,
                disconnectError.message,
            );
            sessionLifecycle.resolveCloseWaiters(currentSession);
            if (
                currentSession.devtoolsSocket &&
                currentSession.devtoolsSocket.readyState === WebSocket.OPEN
            ) {
                currentSession.devtoolsSocket.close();
            }
            sessionLifecycle.unregisterSocket(ws);
            logger.info(
                `[miniapp] miniapp client disconnected: ${currentSession.id}`,
            );
        });

        void bootstrapSession(session);
    });

    return {
        listDebuggableSessions,
        closeMiniApp: (session: MiniAppSession) =>
            windowLifecycle.close(session),
        killMiniApp: (session: MiniAppSession, reason: string) =>
            windowLifecycle.kill(session, reason),
        cleanupLaunchAttempt: (
            attempt: LaunchAttempt,
            reason: string,
            cleanupOptions?: { includeLateResolvedSession?: boolean },
        ) =>
            windowLifecycle.cleanupLaunchAttempt(
                attempt,
                reason,
                cleanupOptions,
            ),
        forceForgetLaunchAttempt: (
            attempt: LaunchAttempt,
            reason: string,
        ) => windowLifecycle.forceForgetLaunchAttempt(attempt, reason),
        evaluateInAppContext: (session: MiniAppSession, expression: string) =>
            cdpRuntime.evaluateInAppContext(session, expression),
        sendMiniAppCdpMessage: (
            session: MiniAppSession,
            message: string,
        ) => cdpRuntime.sendMiniAppCdpMessage(session, message),
    };
};
