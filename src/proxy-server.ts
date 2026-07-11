import { createServer, IncomingMessage, ServerResponse } from "node:http";
import { randomUUID } from "node:crypto";
import WebSocket, { WebSocketServer } from "ws";

import { CliOptions } from "./cli";
import { FridaServerHandle } from "./frida-server";
import { Logger } from "./logger";
import {
    emitMiniAppDiagnostic,
    getMiniAppDiagnosticBundle,
} from "./miniapp-diagnostics";
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
import { debug_server } from "./debug-server";

export const proxy_server = (
    options: CliOptions,
    logger: Logger,
    sessions: Map<string, MiniAppSession>,
    pendingSpawns: Map<string, PendingSpawn>,
    debugServer: ReturnType<typeof debug_server>,
    fridaServer: FridaServerHandle,
) => {
    const pageWss = new WebSocketServer({ noServer: true });
    const legacyWss = new WebSocketServer({ noServer: true });
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

    const isLoopbackRequest = (request: IncomingMessage) => {
        const address = request.socket.remoteAddress?.toLowerCase() ?? "";
        return (
            address === "::1" ||
            address.startsWith("127.") ||
            address.startsWith("::ffff:127.")
        );
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

    const findSession = (sessionId: string) =>
        sessions.get(sessionId) ??
        Array.from(sessions.values()).find(
            (session) => session.requestedAppId === sessionId,
        );

    const getReadySession = (appid: string) => {
        const session = findSession(appid);
        if (
            session?.state !== "ready" ||
            !session.debugSocket ||
            !session.appService
        ) {
            return undefined;
        }
        return session;
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
        emitMiniAppDiagnostic(logger, "launch_rejected", {
            source: "proxy-server",
            launchId: pendingSpawn.id,
            appid,
            boundSessionId: pendingSpawn.boundSessionId ?? null,
            reason: error.message,
        });
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

        const timeout = setTimeout(() => {
            rejectPendingSpawn(
                appid,
                new Error("miniapp did not become ready in time"),
            );
        }, PENDING_SPAWN_TIMEOUT_MS);
        const pendingSpawn = {
            id: randomUUID(),
            appid,
            createdAt: Date.now(),
            windowCursor: fridaServer.getMiniAppWindowCursor(),
            timeout,
            waiters: new Set<PendingSpawnWaiter>(),
        };
        pendingSpawns.set(appid, pendingSpawn);
        emitMiniAppDiagnostic(logger, "launch_registered", {
            launchId: pendingSpawn.id,
            appid,
            createdAt: new Date(pendingSpawn.createdAt).toISOString(),
            windowCursor: pendingSpawn.windowCursor,
            timeoutMs: PENDING_SPAWN_TIMEOUT_MS,
            frida: fridaServer.getStatus(),
        });
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
            requestUrl.pathname === "/api/diagnostics/miniapp"
        ) {
            response.setHeader("Cache-Control", "no-store");
            if (!isLoopbackRequest(request)) {
                sendJson(response, 403, {
                    error: "miniapp diagnostics are only available from loopback",
                });
                return;
            }
            sendJson(response, 200, {
                ...getMiniAppDiagnosticBundle(),
                currentState: {
                    frida: fridaServer.getStatus(),
                    pendingLaunches: Array.from(pendingSpawns.values()).map(
                        (pendingSpawn) => ({
                            launchId: pendingSpawn.id,
                            appid: pendingSpawn.appid,
                            createdAt: new Date(
                                pendingSpawn.createdAt,
                            ).toISOString(),
                            windowCursor: pendingSpawn.windowCursor,
                            boundSessionId:
                                pendingSpawn.boundSessionId ?? null,
                            waiterCount: pendingSpawn.waiters.size,
                        }),
                    ),
                    sessions: listSessions().map((session) =>
                        serializeSession(options, session),
                    ),
                },
            });
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

            if (existingSession) {
                sendJson(response, 409, {
                    error: "existing failed miniapp requires explicit cleanup",
                    miniappId: existingSession.id,
                    cleanupRequired: true,
                });
                return;
            }

            const pendingSpawn = registerPendingSpawn(appid);
            try {
                const status = await spawn_miniapp(appid);
                emitMiniAppDiagnostic(logger, "launch_dispatched", {
                    source: "create",
                    launchId: pendingSpawn.id,
                    appid,
                    windowCursor: pendingSpawn.windowCursor,
                    hostWindow: status.window,
                    wndprocResult: status.messageResult ?? null,
                    wndprocResultIsWindow:
                        status.messageResultIsWindow ?? false,
                });
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
                emitMiniAppDiagnostic(logger, "launch_dispatch_failed", {
                    source: "create",
                    launchId: pendingSpawn.id,
                    appid,
                    error,
                });
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

            let session = findSession(appid);

            if (
                session?.state !== "ready" ||
                !session.debugSocket ||
                !session.appService
            ) {
                const isAlreadyLaunching = pendingSpawns.has(appid);

                if (session && !isAlreadyLaunching) {
                    sendJson(response, 409, {
                        error: "existing failed miniapp requires explicit cleanup",
                        miniappId: session.id,
                        cleanupRequired: true,
                    });
                    return;
                }

                if (!isAlreadyLaunching) {
                    const otherPendingSpawn = findOtherPendingSpawn(appid);
                    if (otherPendingSpawn) {
                        sendJson(response, 409, {
                            error: "another miniapp launch is still pending",
                            pendingAppId: otherPendingSpawn.appid,
                        });
                        return;
                    }

                    const pendingSpawn = registerPendingSpawn(appid);
                    try {
                        const status = await spawn_miniapp(appid);
                        emitMiniAppDiagnostic(logger, "launch_dispatched", {
                            source: "evaluate",
                            launchId: pendingSpawn.id,
                            appid,
                            windowCursor: pendingSpawn.windowCursor,
                            hostWindow: status.window,
                            wndprocResult: status.messageResult ?? null,
                            wndprocResultIsWindow:
                                status.messageResultIsWindow ?? false,
                        });
                        logger.info(
                            `[api] spawn requested for evaluate: ${appid} via ${status.window}; ` +
                                `wndprocResult=${status.messageResult ?? "unavailable"}, ` +
                                `resultIsWindow=${status.messageResultIsWindow ?? false}`,
                        );
                    } catch (error) {
                        emitMiniAppDiagnostic(
                            logger,
                            "launch_dispatch_failed",
                            {
                                source: "evaluate",
                                launchId: pendingSpawn.id,
                                appid,
                                error,
                            },
                        );
                        rejectPendingSpawn(
                            appid,
                            new Error("failed to spawn miniapp"),
                        );
                        logger.error(
                            `[api] spawn miniapp for evaluate failed (${appid}):`,
                            error,
                        );
                        sendJson(response, 500, {
                            error: "failed to spawn miniapp",
                        });
                        return;
                    }
                }

                try {
                    session = await waitForSessionReady(appid);
                } catch (error) {
                    emitMiniAppDiagnostic(logger, "launch_not_ready", {
                        appid,
                        launchId: pendingSpawns.get(appid)?.id ?? null,
                        sessionId: findSession(appid)?.id ?? null,
                        error,
                    });
                    logger.error(
                        `[api] miniapp did not become ready for evaluate (${appid}):`,
                        error,
                    );
                    const failedSession = findSession(appid);
                    sendJson(response, 504, {
                        error: "miniapp did not become ready in time",
                        miniappId: failedSession?.id ?? appid,
                        miniappClosed: false,
                        forcedClose: false,
                        cleanupRequired: failedSession !== undefined,
                    });
                    return;
                }
            }

            try {
                const result = await debugServer.evaluateInAppContext(
                    session,
                    expression,
                );
                sendJson(response, 200, result);
            } catch (error) {
                logger.error(
                    `[api] appContext evaluate failed (${session.id}):`,
                    error,
                );
                sendJson(response, 500, {
                    error: "failed to evaluate in appContext",
                    miniappId: session.id,
                    miniappClosed: false,
                    forcedClose: false,
                    sessionRetained: true,
                });
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

            const session = findSession(sessionId);
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
                const allowLaunchCorrelated =
                    requestUrl.searchParams.get("allowLaunchCorrelated") ===
                    "true";
                emitMiniAppDiagnostic(logger, "close_requested", {
                    requestedId: sessionId,
                    sessionId: session.id,
                    requestedAppId: session.requestedAppId ?? null,
                    state: session.state,
                    launchId: session.launchId ?? null,
                    transportPid: session.transportPid ?? null,
                    hwnd:
                        session.windowHandle === undefined
                            ? null
                            : `0x${session.windowHandle.toString(16)}`,
                    identityVerified: session.windowIdentity !== undefined,
                    appIdConfirmed:
                        session.windowIdentity?.appIdConfirmed ?? false,
                    allowLaunchCorrelated,
                });
                const closeResult = await debugServer.killMiniApp(
                    session,
                    "miniapp despawn requested",
                    { allowLaunchCorrelated },
                );
                if (closeResult.cleanupComplete && session.requestedAppId) {
                    rejectPendingSpawn(
                        session.requestedAppId,
                        new Error("miniapp despawn requested"),
                    );
                }
                emitMiniAppDiagnostic(logger, "close_result", {
                    requestedId: sessionId,
                    sessionId: session.id,
                    ...closeResult,
                });
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

            legacyWss.handleUpgrade(request, socket, head, (ws) => {
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
