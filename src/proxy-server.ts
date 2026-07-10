import { createServer, IncomingMessage, ServerResponse } from "node:http";
import WebSocket, { WebSocketServer } from "ws";

import { CliOptions } from "./cli";
import { FridaServerHandle } from "./frida-server";
import { MiniAppLaunchCoordinator } from "./launch-coordinator";
import { Logger } from "./logger";
import { MiniAppLaunchService } from "./miniapp-launch-service";
import { report_fatal_error } from "./process-guards";
import { get_wechat_status } from "./wechat-host";
import {
    create_sqlcipher_service,
    get_sqlcipher_error_message,
    get_sqlcipher_error_status,
} from "./sqlcipher";
import {
    MiniAppSession,
    touchSession,
    buildTarget,
} from "./session";
import { MiniAppSessionRegistry } from "./session-registry";
import { debug_server } from "./debug-server";

export const proxy_server = (
    options: CliOptions,
    logger: Logger,
    sessionRegistry: MiniAppSessionRegistry,
    launches: MiniAppLaunchCoordinator,
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

    const listDebuggableSessions = () =>
        debugServer.listDebuggableSessions();
    const launchService = new MiniAppLaunchService(
        options,
        logger,
        sessionRegistry,
        launches,
        debugServer,
        fridaServer,
    );

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
                sessionRegistry.serializeAll(options),
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
                    launch: (() => {
                        const attempt = launches.getActive();
                        return attempt
                            ? {
                                  id: attempt.id,
                                  appid: attempt.appid,
                                  phase: attempt.phase,
                                  lastError: attempt.lastError ?? null,
                              }
                            : null;
                    })(),
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

            const existingSession = sessionRegistry.getReady(appid);
            if (existingSession) {
                sendJson(response, 200, {
                    miniappId: existingSession.id,
                    appid,
                    attached: existingSession.attached,
                });
                return;
            }

            try {
                const attempt = launchService.startOrJoin(appid);
                await launchService.waitForDispatch(attempt);
                const readySession = sessionRegistry.getReady(appid);
                sendJson(response, readySession ? 200 : 202, {
                    miniappId: readySession?.id ?? appid,
                    appid,
                    attached: readySession?.attached ?? false,
                    launchId: attempt.id,
                });
            } catch (error) {
                logger.error("[api] spawn miniapp failed:", error);
                sendJson(response, launchService.getStatusCode(error), {
                    error:
                        error instanceof Error
                            ? error.message
                            : "failed to spawn miniapp",
                });
            }
            return;
        }

        if (
            request.method === "POST" &&
            requestUrl.pathname.startsWith("/api/miniapps/") &&
            requestUrl.pathname.endsWith("/app-context/evaluate")
        ) {
            const pathParts = requestUrl.pathname.split("/");
            const encodedAppId = pathParts[pathParts.length - 3];
            let appid = "";
            try {
                appid = encodedAppId ? decodeURIComponent(encodedAppId) : "";
            } catch (error) {
                sendJson(response, 400, { error: "invalid appid" });
                return;
            }
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

            let session = sessionRegistry.find(appid);

            if (
                session?.state !== "ready" ||
                !sessionRegistry.isSocketOpen(session) ||
                !session.appService ||
                launches.isSessionQuarantined(session)
            ) {
                try {
                    const attempt = launchService.startOrJoin(appid);
                    await launchService.waitForDispatch(attempt);
                    session = await launchService.waitForReady(attempt);
                } catch (error) {
                    logger.error(
                        `[api] miniapp launch failed for evaluate (${appid}):`,
                        error,
                    );
                    sendJson(response, launchService.getStatusCode(error), {
                        error:
                            error instanceof Error
                                ? error.message
                                : "miniapp launch failed",
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
                const closeResult = await debugServer.killMiniApp(
                    session,
                    "appContext evaluate failed",
                );
                sendJson(response, 500, {
                    error: "failed to evaluate in appContext",
                    miniappClosed: closeResult.closed,
                    forcedClose: closeResult.forced,
                });
            }
            return;
        }

        if (
            request.method === "DELETE" &&
            requestUrl.pathname.startsWith("/api/miniapps/")
        ) {
            const encodedSessionId = requestUrl.pathname.split("/").pop();
            let sessionId = "";
            try {
                sessionId = encodedSessionId
                    ? decodeURIComponent(encodedSessionId)
                    : "";
            } catch (error) {
                sendJson(response, 400, { error: "invalid miniapp id" });
                return;
            }
            if (!sessionId) {
                sendJson(response, 404, { error: "miniapp not found" });
                return;
            }

            let session = sessionRegistry.find(sessionId);
            const launchAttempt =
                launches.get(sessionId) ??
                (session
                    ? launches.getSessionAttempt(session) ??
                      launches.getOwningAttempt(session)
                    : undefined);
            if (launchAttempt) {
                const forceRelease =
                    requestUrl.searchParams.get("force") === "true";
                launches.requestCancellation(launchAttempt);
                if (
                    launchAttempt.phase === "cleaning" ||
                    launchAttempt.phase === "cleaning-mismatch"
                ) {
                    sendJson(response, 409, {
                        error: "miniapp cleanup is still in progress",
                        launchId: launchAttempt.id,
                    });
                    return;
                }
                const wasBlocked = launchAttempt.phase === "blocked";
                let launchStateCleared = false;
                let closeResult:
                    | Awaited<ReturnType<typeof debugServer.cleanupLaunchAttempt>>
                    | undefined;
                if (wasBlocked) {
                    closeResult = await debugServer.cleanupLaunchAttempt(
                        launchAttempt,
                        "retrying cleanup for blocked miniapp launch",
                        { includeLateResolvedSession: true },
                    );
                    if (
                        forceRelease &&
                        !closeResult.closed &&
                        !closeResult.forced
                    ) {
                        debugServer.forceForgetLaunchAttempt(
                            launchAttempt,
                            "forced launch-state release requested",
                        );
                    }
                    if (
                        closeResult.closed ||
                        closeResult.forced ||
                        forceRelease
                    ) {
                        launchStateCleared = launches.clearBlocked(launchAttempt);
                    }
                } else {
                    await launches.fail(
                        launchAttempt,
                        new Error("miniapp despawn requested while launching"),
                        async () => {
                            closeResult = await debugServer.cleanupLaunchAttempt(
                                launchAttempt,
                                "miniapp despawn requested while launching",
                                { includeLateResolvedSession: true },
                            );
                            return (
                                closeResult.closed ||
                                closeResult.forced ||
                                (!launchAttempt.session &&
                                    launchAttempt.dispatchStartedAt === undefined)
                            );
                        },
                    );
                    launchStateCleared =
                        launches.get(launchAttempt.appid) === undefined;
                }
                const cleanupConfirmed = launchStateCleared;
                sendJson(response, cleanupConfirmed ? 200 : 409, {
                    miniappId: sessionId,
                    attached: false,
                    miniappClosed: closeResult?.closed ?? false,
                    forcedClose: closeResult?.forced ?? false,
                    launchStateCleared,
                    forcedLaunchRelease:
                        forceRelease && launchStateCleared,
                });
                return;
            }

            session ??= sessionRegistry.find(sessionId);
            if (!session) {
                sendJson(response, 404, { error: "miniapp not found" });
                return;
            }

            try {
                const closeResult = await debugServer.killMiniApp(
                    session,
                    "miniapp despawn requested",
                );
                const cleanupConfirmed =
                    closeResult.closed || closeResult.forced;
                sendJson(response, cleanupConfirmed ? 200 : 409, {
                    miniappId: session.id,
                    attached: session.attached,
                    miniappClosed: closeResult.closed,
                    forcedClose: closeResult.forced,
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
            const session = sessionId
                ? sessionRegistry.getExact(sessionId)
                : undefined;
            if (
                !session ||
                session.state !== "ready" ||
                !sessionRegistry.isSocketOpen(session) ||
                launches.isSessionQuarantined(session)
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
