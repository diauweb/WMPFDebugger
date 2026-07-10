import WebSocket from "ws";

import { Logger } from "./logger";
import { MiniAppSession, touchSession } from "./session";
import { MiniAppSessionRegistry } from "./session-registry";

export class DebugSessionLifecycle {
    private readonly socketSessions = new Map<WebSocket, MiniAppSession>();

    constructor(
        private readonly logger: Logger,
        private readonly sessions: MiniAppSessionRegistry,
    ) {}

    registerSocket(socket: WebSocket, session: MiniAppSession) {
        this.socketSessions.set(socket, session);
    }

    getBySocket(socket: WebSocket) {
        return this.socketSessions.get(socket);
    }

    unregisterSocket(socket: WebSocket) {
        this.socketSessions.delete(socket);
    }

    stopForegroundKeepAlive(session: MiniAppSession) {
        if (session.foregroundKeepAlive) {
            clearInterval(session.foregroundKeepAlive);
            session.foregroundKeepAlive = undefined;
        }
    }

    rejectPendingWork(session: MiniAppSession, message: string) {
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
    }

    resolveCloseWaiters(session: MiniAppSession) {
        for (const waiter of session.closeWaiters) {
            clearTimeout(waiter.timeout);
            waiter.resolve();
        }
        session.closeWaiters.clear();
    }

    detach(session: MiniAppSession, reason: string) {
        const debugSocket = session.debugSocket;
        const devtoolsSocket = session.devtoolsSocket;

        session.debugSocket = undefined;
        session.devtoolsSocket = undefined;
        session.appService = undefined;
        session.appServiceBootstrap = undefined;
        session.attached = false;
        session.state = "closing";
        session.lastError = reason;
        touchSession(session);

        this.stopForegroundKeepAlive(session);
        this.rejectPendingWork(session, reason);
        this.resolveCloseWaiters(session);
        this.sessions.remove(session);

        if (debugSocket) {
            this.socketSessions.delete(debugSocket);
        }

        this.closeWebSocket(devtoolsSocket, 1001, reason);
        this.closeWebSocket(debugSocket, 1011, reason, true);
    }

    private closeWebSocket(
        socket: WebSocket | undefined,
        code: number,
        reason: string,
        force = false,
    ) {
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
            this.logger.main_debug(
                `[miniapp] websocket close failed; terminating: ${String(error)}`,
            );
            socket.terminate();
        }
    }
}
