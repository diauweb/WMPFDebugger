import { createServer, IncomingMessage, ServerResponse } from "node:http";
import { randomUUID } from "node:crypto";
import WebSocket, { WebSocketServer } from "ws";

import { CliOptions } from "./cli";
import { FridaServerHandle } from "./frida-server";
import { Logger } from "./logger";
import { report_fatal_error } from "./process-guards";
import { get_wechat_status, spawn_miniapp } from "./wechat-host";
import {
    create_sqlcipher_service,
    get_sqlcipher_error_message,
    get_sqlcipher_error_status,
} from "./sqlcipher";
import {
    MiniAppSession,
    PendingSpawnWaiter,
    PendingSpawn,
    PENDING_SPAWN_TIMEOUT_MS,
    touchSession,
    serializeSession,
    buildTarget,
} from "./session";
import { debug_server, isDeadSessionFailure } from "./debug-server";

export const proxy_server = (
    options: CliOptions,
    logger: Logger,
    sessions: Map<string, MiniAppSession>,
    pendingSpawns: Map<string, PendingSpawn>,
    debugServer: ReturnType<typeof debug_server>,
    fridaServer: FridaServerHandle,
) => {
    const pageWss = new WebSocketServer({ noServer: true });
    // Root websocket path: the quick-start entry point
    // (devtools://devtools/bundled/inspector.html?ws=127.0.0.1:62000).
    const rootWss = new WebSocketServer({ noServer: true });
    const evaluationTails = new Map<string, Promise<void>>();
    const sqlcipherService = create_sqlcipher_service(
        logger,
        options.sqlcipherDbRoot,
    );
    const server = createServer();
    server.on("error", (error) => {
        report_fatal_error(logger, "[server] proxy server error", error);
    });

    const sendJson = (
        response: ServerResponse<IncomingMessage>,
        statusCode: number,
        payload: unknown,
    ) => {
        response.statusCode = statusCode;
        response.setHeader("Content-Type", "application/json; charset=utf-8");
        response.end(JSON.stringify(payload));
    };

    const readJsonBody = async (request: IncomingMessage) => {
        const chunks: Buffer[] = [];
        for await (const chunk of request) {
            chunks.push(
                Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk),
            );
        }
        const rawBody = Buffer.concat(chunks).toString("utf8").trim();
        return rawBody.length > 0
            ? (JSON.parse(rawBody) as Record<string, unknown>)
            : {};
    };

    const listSessions = () =>
        Array.from(sessions.values()).sort(
            (left, right) => left.createdAt - right.createdAt,
        );

    const listDebuggableSessions = () =>
        debugServer
            .listDebuggableSessions()
            .sort((left, right) => left.createdAt - right.createdAt);

    const listSessionCandidates = (sessionId: string) =>
        Array.from(new Set(sessions.values()))
            .filter(
                (session) =>
                    session.id === sessionId ||
                    session.requestedAppId === sessionId,
            )
            .sort((left, right) => {
                const leftReady =
                    left.state === "ready" &&
                    left.debugSocket?.readyState === WebSocket.OPEN &&
                    left.appService !== undefined;
                const rightReady =
                    right.state === "ready" &&
                    right.debugSocket?.readyState === WebSocket.OPEN &&
                    right.appService !== undefined;
                if (leftReady !== rightReady) {
                    return leftReady ? -1 : 1;
                }
                const leftLastSuccess =
                    left.lastEvaluationSucceededAt ?? 0;
                const rightLastSuccess =
                    right.lastEvaluationSucceededAt ?? 0;
                if (leftLastSuccess !== rightLastSuccess) {
                    return rightLastSuccess - leftLastSuccess;
                }
                if (left.evaluationFailures !== right.evaluationFailures) {
                    return left.evaluationFailures - right.evaluationFailures;
                }
                return left.createdAt - right.createdAt;
            });

    const findSession = (sessionId: string) =>
        listSessionCandidates(sessionId)[0];

    const findCloseSession = (sessionId: string) =>
        listSessionCandidates(sessionId).sort((left, right) => {
            const leftHasWindow = left.windowHandle !== undefined ? 1 : 0;
            const rightHasWindow = right.windowHandle !== undefined ? 1 : 0;
            if (leftHasWindow !== rightHasWindow) {
                return rightHasWindow - leftHasWindow;
            }
            return left.createdAt - right.createdAt;
        })[0];

    const listReadySessions = (appid: string) =>
        listSessionCandidates(appid).filter(
            (session) =>
                session.state === "ready" &&
                session.debugSocket?.readyState === WebSocket.OPEN &&
                session.appService !== undefined,
        );

    const getReadySession = (appid: string) => {
        return listReadySessions(appid)[0];
    };

    const withAppEvaluationLock = async <T>(
        appid: string,
        operation: () => Promise<T>,
    ) => {
        const previous = evaluationTails.get(appid) ?? Promise.resolve();
        let release = () => {};
        const gate = new Promise<void>((resolve) => {
            release = resolve;
        });
        const queued = previous.catch(() => undefined).then(() => gate);
        evaluationTails.set(appid, queued);
        await previous.catch(() => undefined);
        try {
            return await operation();
        } finally {
            release();
            if (evaluationTails.get(appid) === queued) {
                evaluationTails.delete(appid);
            }
        }
    };

    const findOtherPendingSpawn = (appid: string) =>
        Array.from(pendingSpawns.values()).find(
            (pendingSpawn) => pendingSpawn.appid !== appid,
        );

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

    const registerPendingSpawn = (appid: string) => {
        const existing = pendingSpawns.get(appid);
        if (existing) {
            return existing;
        }

        let pendingSpawn: PendingSpawn;
        const timeout = setTimeout(() => {
            const retainedSession =
                debugServer.retainPendingLaunchWindow(pendingSpawn);
            rejectPendingSpawn(
                appid,
                new Error(
                    retainedSession
                        ? "miniapp launched but did not attach; launch-correlated window retained for explicit cleanup"
                        : "miniapp did not become ready in time",
                ),
            );
        }, PENDING_SPAWN_TIMEOUT_MS);
        pendingSpawn = {
            id: randomUUID(),
            appid,
            createdAt: Date.now(),
            windowCursor: fridaServer.getMiniAppWindowCursor(),
            timeout,
            waiters: new Set<PendingSpawnWaiter>(),
        };
        pendingSpawns.set(appid, pendingSpawn);

        return pendingSpawn;
    };

    const waitForSessionReady = (appid: string) =>
        new Promise<MiniAppSession>((resolve, reject) => {
            const readySession = getReadySession(appid);
            if (readySession) {
                resolve(readySession);
                return;
            }

            const pendingSpawn = pendingSpawns.get(appid);
            if (!pendingSpawn) {
                reject(new Error("miniapp is not launching"));
                return;
            }

            pendingSpawn.waiters.add({ resolve, reject });
        });

    const bindDevTools = (session: MiniAppSession, ws: WebSocket) => {
        if (session.devtoolsSocket && session.devtoolsSocket.readyState === WebSocket.OPEN) {
            ws.close(1008, "Miniapp already attached");
            return;
        }

        session.devtoolsSocket = ws;
        session.attached = true;
        touchSession(session);
        logger.info(`[cdp] CDP client connected: ${session.id}`);

        ws.on("message", (message) => {
            try {
                debugServer.sendMiniAppCdpMessage(session, message.toString());
            } catch (error) {
                logger.error(`[cdp] CDP proxy err (${session.id}):`, error);
                ws.close();
            }
        });
        ws.on("error", (error) => {
            logger.error(`[cdp] CDP client err (${session.id}):`, error);
        });
        ws.on("close", () => {
            if (session.devtoolsSocket === ws) {
                session.devtoolsSocket = undefined;
                session.attached = false;
                touchSession(session);
            }
            logger.info(`[cdp] CDP client disconnected: ${session.id}`);
        });
    };

    server.on("request", async (request, response) => {
        const requestUrl = new URL(
            request.url || "/",
            `http://127.0.0.1:${options.cdpPort}`,
        );

        if (
            request.method === "GET" &&
            (requestUrl.pathname === "/json" ||
                requestUrl.pathname === "/json/list")
        ) {
            sendJson(
                response,
                200,
                listDebuggableSessions().map((session) =>
                    buildTarget(options, session),
                ),
            );
            return;
        }

        if (request.method === "GET" && requestUrl.pathname === "/json/version") {
            sendJson(response, 200, {
                Browser: "WMPFDebugger",
                "Protocol-Version": "1.3",
            });
            return;
        }

        if (request.method === "GET" && requestUrl.pathname === "/api/miniapps") {
            sendJson(
                response,
                200,
                listSessions().map((session) => serializeSession(options, session)),
            );
            return;
        }

        if (
            request.method === "GET" &&
            requestUrl.pathname === "/api/wechat/status"
        ) {
            try {
                const status = await get_wechat_status();
                sendJson(response, 200, {
                    alive: status.window === "main",
                    window: status.window,
                    hook: fridaServer.getStatus(),
                });
            } catch (error) {
                logger.error("[api] failed to query WeChat status:", error);
                sendJson(response, 500, {
                    error: "failed to query WeChat status",
                });
            }
            return;
        }

        if (
            request.method === "GET" &&
            requestUrl.pathname === "/api/sqlcipher/databases"
        ) {
            try {
                sendJson(response, 200, {
                    databases: sqlcipherService.listDatabases(),
                });
            } catch (error) {
                const statusCode = get_sqlcipher_error_status(error);
                if (statusCode >= 500) {
                    logger.error("[api] SQLCipher database list failed:", error);
                }
                sendJson(response, statusCode, {
                    error: get_sqlcipher_error_message(error),
                });
            }
            return;
        }

        if (
            request.method === "POST" &&
            requestUrl.pathname === "/api/sqlcipher/query"
        ) {
            let body: Record<string, unknown>;
            try {
                body = await readJsonBody(request);
            } catch (error) {
                sendJson(response, 400, { error: "invalid JSON body" });
                return;
            }

            try {
                const result = sqlcipherService.query({
                    database:
                        typeof body.database === "string" ? body.database : "",
                    sql: typeof body.sql === "string" ? body.sql : "",
                    params:
                        body.params === undefined
                            ? undefined
                            : (body.params as any),
                    maxRows:
                        body.maxRows === undefined
                            ? undefined
                            : (body.maxRows as any),
                });
                sendJson(response, 200, result);
            } catch (error) {
                const statusCode = get_sqlcipher_error_status(error);
                if (statusCode >= 500) {
                    logger.error("[api] SQLCipher query failed:", error);
                }
                sendJson(response, statusCode, {
                    error: get_sqlcipher_error_message(error),
                });
            }
            return;
        }

        if (
            request.method === "POST" &&
            requestUrl.pathname === "/api/miniapps"
        ) {
            let body: Record<string, unknown>;
            try {
                body = await readJsonBody(request);
            } catch (error) {
                sendJson(response, 400, { error: "invalid JSON body" });
                return;
            }

            const appid =
                typeof body.appid === "string" ? body.appid.trim() : "";
            if (!appid) {
                sendJson(response, 400, { error: "appid is required" });
                return;
            }

            const existingSession = findSession(appid);
            if (
                existingSession?.state === "ready" &&
                existingSession.debugSocket &&
                existingSession.appService
            ) {
                sendJson(response, 200, {
                    miniappId: existingSession.id,
                    appid,
                    attached: existingSession.attached,
                });
                return;
            }

            if (pendingSpawns.has(appid)) {
                sendJson(response, 202, {
                    miniappId: existingSession?.id ?? appid,
                    appid,
                    attached: false,
                });
                return;
            }

            const otherPendingSpawn = findOtherPendingSpawn(appid);
            if (otherPendingSpawn) {
                sendJson(response, 409, {
                    error: "another miniapp launch is still pending",
                    pendingAppId: otherPendingSpawn.appid,
                });
                return;
            }

            // A stale/failed session must never block a new launch. Retire it
            // (best-effort window close when a safe HWND is known) and proceed.
            if (existingSession) {
                await debugServer.retireStaleSession(existingSession);
            }

            const pendingSpawn = registerPendingSpawn(appid);
            try {
                const status = await spawn_miniapp(appid);

                logger.info(
                    `[api] spawn requested: ${appid} via ${status.window}; ` +
                        `wndprocResult=${status.messageResult ?? "unavailable"}, ` +
                        `resultIsWindow=${status.messageResultIsWindow ?? false}`,
                );
                sendJson(response, 202, {
                    miniappId: appid,
                    appid,
                    attached: false,
                });
            } catch (error) {

                rejectPendingSpawn(
                    appid,
                    new Error("failed to spawn miniapp"),
                );
                logger.error("[api] spawn miniapp failed:", error);
                sendJson(response, 500, { error: "failed to spawn miniapp" });
            }
            return;
        }

        if (
            request.method === "POST" &&
            requestUrl.pathname.startsWith("/api/miniapps/") &&
            requestUrl.pathname.endsWith("/app-context/evaluate")
        ) {
            const pathParts = requestUrl.pathname.split("/");
            const appid = pathParts[pathParts.length - 3];
            if (!appid) {
                sendJson(response, 404, { error: "miniapp not found" });
                return;
            }

            let body: Record<string, unknown>;
            try {
                body = await readJsonBody(request);
            } catch (error) {
                sendJson(response, 400, { error: "invalid JSON body" });
                return;
            }

            const expression =
                typeof body.expression === "string" ? body.expression : "";
            if (!expression) {
                sendJson(response, 400, { error: "expression is required" });
                return;
            }

            let session: MiniAppSession | undefined = findSession(appid);

            const spawnForEvaluate = async () => {
                if (!pendingSpawns.has(appid)) {
                    const otherPendingSpawn = findOtherPendingSpawn(appid);
                    if (otherPendingSpawn) {
                        const conflict = new Error(
                            "another miniapp launch is still pending",
                        );
                        (conflict as any).pendingAppId =
                            otherPendingSpawn.appid;
                        throw conflict;
                    }

                    const pendingSpawn = registerPendingSpawn(appid);
                    try {
                        const status = await spawn_miniapp(appid);

                        logger.info(
                            `[api] spawn requested for evaluate: ${appid} via ${status.window}; ` +
                                `wndprocResult=${status.messageResult ?? "unavailable"}, ` +
                                `resultIsWindow=${status.messageResultIsWindow ?? false}`,
                        );
                    } catch (error) {

                        rejectPendingSpawn(
                            appid,
                            new Error("failed to spawn miniapp"),
                        );
                        logger.error(
                            `[api] spawn miniapp for evaluate failed (${appid}):`,
                            error,
                        );
                        const spawnError = new Error(
                            "failed to spawn miniapp",
                        );
                        (spawnError as any).statusCode = 500;
                        throw spawnError;
                    }
                }
                return waitForSessionReady(appid);
            };

            const evaluateOne = async (candidate: MiniAppSession) => {

                const result = await debugServer.evaluateInAppContext(
                    candidate,
                    expression,
                );
                const activeSession = debugServer.promoteSessionAttachment(
                    appid,
                    candidate,
                );
                return { result, activeSession };
            };

            let attempt = 0;
            while (attempt < 2) {
                attempt += 1;
                let readySession = getReadySession(appid);
                if (!readySession) {
                    if (session && !pendingSpawns.has(appid)) {
                        await debugServer.retireStaleSession(session, {
                            force: true,
                        });
                        session = undefined;
                    }
                    try {
                        readySession = await spawnForEvaluate();
                    } catch (error) {
                        const pendingAppId = (error as any)?.pendingAppId;
                        if (pendingAppId) {
                            sendJson(response, 409, {
                                error: "another miniapp launch is still pending",
                                pendingAppId,
                            });
                            return;
                        }
                        if ((error as any)?.statusCode === 500) {
                            sendJson(response, 500, {
                                error: "failed to spawn miniapp",
                            });
                            return;
                        }
                        const failedSession = findSession(appid);

                        logger.error(
                            `[api] miniapp did not become ready for evaluate (${appid}):`,
                            error,
                        );
                        sendJson(response, 504, {
                            error: "miniapp did not become ready in time",
                            miniappId: failedSession?.id ?? appid,
                            miniappClosed: false,
                            forcedClose: false,
                            cleanupRequired:
                                failedSession?.windowHandle !== undefined,
                        });
                        return;
                    }
                }

                if (!readySession) {
                    sendJson(response, 500, {
                        error: "miniapp session unavailable",
                    });
                    return;
                }

                const evaluation = await withAppEvaluationLock(
                    appid,
                    async () => {
                        const candidates = [
                            readySession,
                            ...listReadySessions(appid).filter(
                                (candidate) => candidate !== readySession,
                            ),
                        ];
                        const failures: Array<{
                            traceId: string;
                            sessionId: string;
                            message: string;
                        }> = [];
                        let deadCount = 0;
                        for (const candidate of candidates) {
                            try {
                                const evaluated = await evaluateOne(candidate);
                                return {
                                    ok: true as const,
                                    ...evaluated,
                                    failures,
                                };
                            } catch (error) {
                                const message =
                                    error instanceof Error
                                        ? error.message
                                        : String(error);
                                failures.push({
                                    traceId: candidate.traceId,
                                    sessionId: candidate.id,
                                    message,
                                });
                                logger.error(
                                    `[api] appContext evaluate candidate failed (${candidate.id}, ${candidate.traceId}):`,
                                    error,
                                );
                                if (isDeadSessionFailure(error)) {
                                    await debugServer.retireStaleSession(
                                        candidate,
                                        { force: true },
                                    );
                                    deadCount += 1;
                                }
                            }
                        }
                        return {
                            ok: false as const,
                            failures,
                            deadCount,
                            preferred: readySession,
                        };
                    },
                );

                if (evaluation.ok) {
                    sendJson(response, 200, {
                        ...evaluation.result,
                        attachment: {
                            traceId: evaluation.activeSession.traceId,
                            attempted: evaluation.failures.length + 1,
                        },
                    });
                    return;
                }

                // The miniapp died while evaluating. Relaunch once and retry.
                if (
                    attempt < 2 &&
                    evaluation.deadCount > 0 &&
                    evaluation.deadCount === evaluation.failures.length
                ) {
                    session = findSession(appid);
                    continue;
                }

                sendJson(response, 500, {
                    error: "all miniapp attachments failed to evaluate in appContext",
                    miniappId: evaluation.preferred.id,
                    attemptedAttachments: evaluation.failures,
                    miniappClosed: evaluation.deadCount > 0,
                    forcedClose: false,
                    sessionRetained: false,
                });
                return;
            }
            return;
        }

        if (
            request.method === "DELETE" &&
            requestUrl.pathname.startsWith("/api/miniapps/")
        ) {
            const sessionId = requestUrl.pathname.split("/").pop();
            if (!sessionId) {
                sendJson(response, 404, { error: "miniapp not found" });
                return;
            }

            const session = findCloseSession(sessionId);
            if (!session) {
                if (pendingSpawns.has(sessionId)) {
                    rejectPendingSpawn(
                        sessionId,
                        new Error("miniapp despawn requested while launching"),
                    );
                    sendJson(response, 202, {
                        miniappId: sessionId,
                        attached: false,
                        miniappClosed: false,
                    });
                    return;
                }
                sendJson(response, 404, { error: "miniapp not found" });
                return;
            }

            try {
                const closeResult = await debugServer.killMiniApp(
                    session,
                    "miniapp despawn requested",
                );
                if (closeResult.cleanupComplete && session.requestedAppId) {
                    rejectPendingSpawn(
                        session.requestedAppId,
                        new Error("miniapp despawn requested"),
                    );
                }

                sendJson(response, closeResult.cleanupComplete ? 200 : 409, {
                    ...(closeResult.error
                        ? { error: closeResult.error }
                        : {}),
                    miniappId: session.id,
                    attached: session.attached,
                    miniappClosed: closeResult.closed,
                    alreadyGone: closeResult.alreadyGone,
                    cleanupComplete: closeResult.cleanupComplete,
                    forcedClose: closeResult.forced,
                    launchCorrelatedClose:
                        closeResult.launchCorrelatedClose,
                });
            } catch (error) {
                logger.error(
                    `[api] despawn miniapp failed (${session.id}):`,
                    error,
                );
                sendJson(response, 500, {
                    error: "failed to despawn miniapp",
                });
            }
            return;
        }

        sendJson(response, 404, { error: "not found" });
    });

    server.on("upgrade", (request, socket, head) => {
        const requestUrl = new URL(
            request.url || "/",
            `http://127.0.0.1:${options.cdpPort}`,
        );

        if (requestUrl.pathname.startsWith("/devtools/page/")) {
            const sessionId = requestUrl.pathname.split("/").pop();
            const session = sessionId ? sessions.get(sessionId) : undefined;
            if (
                !session ||
                session.state !== "ready" ||
                !session.debugSocket
            ) {
                socket.write("HTTP/1.1 404 Not Found\r\n\r\n");
                socket.destroy();
                return;
            }

            pageWss.handleUpgrade(request, socket, head, (ws) => {
                bindDevTools(session, ws);
            });
            return;
        }

        if (requestUrl.pathname === "/") {
            const activeSessions = listDebuggableSessions();
            if (activeSessions.length !== 1) {
                socket.write("HTTP/1.1 409 Conflict\r\n\r\n");
                socket.destroy();
                return;
            }

            rootWss.handleUpgrade(request, socket, head, (ws) => {
                bindDevTools(activeSessions[0], ws);
            });
            return;
        }

        socket.write("HTTP/1.1 404 Not Found\r\n\r\n");
        socket.destroy();
    });

    server.listen(options.cdpPort, () => {
        logger.info(
            `[server] proxy server running on http://localhost:${options.cdpPort}`,
        );
        logger.info(
            `[server] targets: http://127.0.0.1:${options.cdpPort}/json/list`,
        );
    });
};
