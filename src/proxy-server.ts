import { createServer, IncomingMessage, ServerResponse } from "node:http";
import WebSocket, { WebSocketServer } from "ws";

import { CliOptions } from "./cli";
import { FridaServerHandle } from "./frida-server";
import { Logger } from "./logger";
import { report_fatal_error } from "./process-guards";
import { get_wechat_status, spawn_miniapp } from "./wechat-host";
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

    const getReadySession = (appid: string) => {
        const session = sessions.get(appid);
        if (!session?.debugSocket || !session.appService) {
            return undefined;
        }
        return session;
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
            appid,
            createdAt: Date.now(),
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

            const existingSession = sessions.get(appid);
            if (existingSession) {
                sendJson(response, 200, {
                    miniappId: existingSession.id,
                    appid,
                    attached: existingSession.attached,
                });
                return;
            }

            if (pendingSpawns.has(appid)) {
                sendJson(response, 202, {
                    miniappId: appid,
                    appid,
                    attached: false,
                });
                return;
            }

            registerPendingSpawn(appid);
            try {
                const status = await spawn_miniapp(appid);
                logger.info(
                    `[api] spawn requested: ${appid} via ${status.window}`,
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

            let session = sessions.get(appid);

            if (!session?.debugSocket) {
                const isAlreadyLaunching = pendingSpawns.has(appid);

                if (!isAlreadyLaunching) {
                    registerPendingSpawn(appid);
                    try {
                        const status = await spawn_miniapp(appid);
                        logger.info(
                            `[api] spawn requested for evaluate: ${appid} via ${status.window}`,
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
                        sendJson(response, 500, {
                            error: "failed to spawn miniapp",
                        });
                        return;
                    }
                }

                try {
                    session = await waitForSessionReady(appid);
                } catch (error) {
                    logger.error(
                        `[api] miniapp did not become ready for evaluate (${appid}):`,
                        error,
                    );
                    sendJson(response, 504, {
                        error: "miniapp did not become ready in time",
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

            if (pendingSpawns.has(sessionId)) {
                sendJson(response, 409, {
                    error: "miniapp is still launching",
                });
                return;
            }

            const session = sessions.get(sessionId);
            if (!session) {
                sendJson(response, 404, { error: "miniapp not found" });
                return;
            }
            if (!session.debugSocket || !session.appService) {
                sendJson(response, 409, {
                    error: "miniapp is not ready to despawn",
                });
                return;
            }

            try {
                await debugServer.closeMiniApp(session);
                sendJson(response, 200, {
                    miniappId: session.id,
                    attached: session.attached,
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
            if (!session || !session.debugSocket) {
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
