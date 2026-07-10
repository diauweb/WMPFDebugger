import WebSocket from "ws";

import { DebugSessionLifecycle } from "./debug-session-lifecycle";
import type { FridaServerHandle } from "./frida-server";
import {
    LaunchAttempt,
    MiniAppLaunchCoordinator,
} from "./launch-coordinator";
import { Logger } from "./logger";
import {
    CloseWaiter,
    INTERNAL_CDP_TIMEOUT_MS,
    MiniAppSession,
    touchSession,
} from "./session";
import { close_window, is_window } from "./wechat-host";
import { drainCorrelatedWindows } from "./window-drain";

const WINDOW_CLAIM_GRACE_MS = 1_000;
const WINDOW_QUIET_MS = 2_000;
const WINDOW_POLL_MS = 100;
const WINDOW_DRAIN_TIMEOUT_MS = 10_000;
const SOCKET_CLOSE_CONFIRM_MS = 750;

const sleep = (ms: number) =>
    new Promise<void>((resolve) => setTimeout(resolve, ms));

const formatError = (error: unknown) =>
    error instanceof Error ? error.message : String(error ?? "");

export class MiniAppWindowLifecycle {
    private readonly closeOperations = new WeakMap<
        MiniAppSession,
        Promise<{ closed: boolean; forced: boolean }>
    >();

    constructor(
        private readonly logger: Logger,
        private readonly launches: MiniAppLaunchCoordinator,
        private readonly frida: Pick<FridaServerHandle, "claimMiniAppWindow">,
        private readonly sessions: DebugSessionLifecycle,
    ) {}

    rememberWindow(session: MiniAppSession) {
        if (session.windowHandle !== undefined) {
            try {
                if (is_window(session.windowHandle)) {
                    return session.windowHandle;
                }
                session.windowClosureObserved = true;
            } catch (error) {
                this.logger.error(
                    `[miniapp] failed to validate cached hwnd for ${session.id}:`,
                    error,
                );
            }
            session.windowHandle = undefined;
        }

        try {
            const claimBaseline = session.launchStartedAt ?? session.createdAt;
            while (session.windowHandle === undefined) {
                const miniAppWindow = this.frida.claimMiniAppWindow({
                    createdAfter: claimBaseline,
                    graceMs:
                        session.launchStartedAt === undefined
                            ? WINDOW_CLAIM_GRACE_MS
                            : 0,
                });
                if (!miniAppWindow) {
                    break;
                }
                if (!is_window(miniAppWindow.handle)) {
                    session.windowClosureObserved = true;
                    continue;
                }
                session.windowHandle = miniAppWindow.handle;
                this.logger.info(
                    `[miniapp] remembered window hwnd for ${session.id}: 0x${miniAppWindow.handle.toString(16)}`,
                );
            }
        } catch (error) {
            this.logger.error(
                `[miniapp] failed to remember window hwnd for ${session.id}:`,
                error,
            );
        }

        return session.windowHandle;
    }

    close(session: MiniAppSession) {
        return this.closeSessionWindows(session);
    }

    kill(
        session: MiniAppSession,
        reason: string,
    ): Promise<{ closed: boolean; forced: boolean }> {
        const existingOperation = this.closeOperations.get(session);
        if (existingOperation) {
            return existingOperation;
        }

        const operation = (async () => {
            const forced = !session.debugSocket;
            session.state = "closing";
            session.lastError = reason;
            touchSession(session);
            this.sessions.stopForegroundKeepAlive(session);

            try {
                await this.closeSessionWindows(session);
                return { closed: true, forced };
            } catch (error) {
                this.logger.error(
                    `[miniapp] window close failed for ${session.id}; keeping session attached for retry:`,
                    error,
                );
                session.lastError = `miniapp close failed: ${formatError(error)}`;
                touchSession(session);
                return { closed: false, forced: false };
            }
        })();
        this.closeOperations.set(session, operation);
        const clearOperation = () => {
            if (this.closeOperations.get(session) === operation) {
                this.closeOperations.delete(session);
            }
        };
        void operation.then(clearOperation, clearOperation);
        return operation;
    }

    async cleanupLaunchAttempt(
        attempt: LaunchAttempt,
        reason: string,
        options?: { includeLateResolvedSession?: boolean },
    ) {
        const cleanupSessions = new Set(attempt.cleanupSessions ?? []);
        if (attempt.session) {
            cleanupSessions.add(attempt.session);
        }
        if (
            options?.includeLateResolvedSession &&
            attempt.lateResolvedSession
        ) {
            cleanupSessions.add(attempt.lateResolvedSession);
            this.launches.addCleanupSession(
                attempt,
                attempt.lateResolvedSession,
            );
        }
        if (cleanupSessions.size > 0) {
            let forced = false;
            for (const cleanupSession of cleanupSessions) {
                const closeResult = await this.kill(cleanupSession, reason);
                if (!closeResult.closed && !closeResult.forced) {
                    return { closed: false, forced: false };
                }
                forced ||= closeResult.forced;
                this.launches.completeCleanupSession(attempt, cleanupSession);
                if (attempt.session === cleanupSession) {
                    attempt.session = undefined;
                }
                if (attempt.lateResolvedSession === cleanupSession) {
                    attempt.lateResolvedSession = undefined;
                }
            }
            if ((attempt.cleanupSessions?.size ?? 0) === 0) {
                attempt.identityMismatch = false;
            }
            return { closed: true, forced };
        }

        if (
            attempt.dispatchStartedAt === undefined &&
            attempt.windowHandle === undefined
        ) {
            return { closed: false, forced: false };
        }
        if (attempt.identityMismatch) {
            this.logger.error(
                `[miniapp] launch ${attempt.id} observed a mismatched runtime without a cleanup session`,
            );
            return { closed: false, forced: false };
        }

        const drainResult = await drainCorrelatedWindows({
            initialHandle: attempt.windowHandle,
            previouslyObserved: attempt.windowClosureObserved,
            claim: () =>
                this.frida.claimMiniAppWindow({
                    createdAfter: attempt.dispatchStartedAt,
                })?.handle,
            isLive: is_window,
            close: (windowHandle) =>
                this.requestWindowClose(
                    windowHandle,
                    `unconnected launch ${attempt.id}`,
                ),
            onPendingHandle: (windowHandle) => {
                attempt.windowHandle = windowHandle;
            },
            quietMs: WINDOW_QUIET_MS,
            timeoutMs: WINDOW_DRAIN_TIMEOUT_MS,
            pollMs: WINDOW_POLL_MS,
        });
        attempt.windowClosureObserved ||= drainResult.observed;

        if (drainResult.closed) {
            return { closed: true, forced: true };
        }
        if (drainResult.observed) {
            this.logger.error(
                `[miniapp] launch ${attempt.id} kept producing correlated windows during cleanup`,
            );
            return { closed: false, forced: false };
        }
        this.logger.error(
            `[miniapp] launch ${attempt.id} timed out without a correlated socket or window; refusing to guess an HWND`,
        );
        return { closed: false, forced: false };
    }

    forceForgetLaunchAttempt(attempt: LaunchAttempt, reason: string) {
        const sessionsToForget = new Set(attempt.cleanupSessions ?? []);
        if (attempt.session) {
            sessionsToForget.add(attempt.session);
        }
        if (attempt.lateResolvedSession) {
            sessionsToForget.add(attempt.lateResolvedSession);
        }
        for (const session of sessionsToForget) {
            this.sessions.detach(session, reason);
        }
        attempt.session = undefined;
        attempt.lateResolvedSession = undefined;
        attempt.cleanupSessions?.clear();
        return sessionsToForget.size > 0;
    }

    private async closeSessionWindows(session: MiniAppSession) {
        const claimBaseline = session.launchStartedAt ?? session.createdAt;
        const drainSessionWindows = (
            initialHandle: number | undefined,
            previouslyObserved: boolean | undefined,
            useIdentityFallback = false,
            fallbackRequiresOpenSocket = false,
        ) =>
            drainCorrelatedWindows({
                initialHandle,
                previouslyObserved,
                claim: () => {
                    const correlatedWindow = this.frida.claimMiniAppWindow({
                        createdAfter: claimBaseline,
                        graceMs:
                            session.launchStartedAt === undefined
                                ? WINDOW_CLAIM_GRACE_MS
                                : 0,
                    });
                    if (correlatedWindow) {
                        return correlatedWindow.handle;
                    }
                    const socketStillOpen =
                        session.debugSocket !== undefined &&
                        session.debugSocket.readyState !== WebSocket.CLOSED;
                    if (
                        useIdentityFallback &&
                        (!fallbackRequiresOpenSocket || socketStillOpen)
                    ) {
                        return this.frida.claimMiniAppWindow({
                            fallbackToLatest: true,
                        })?.handle;
                    }
                    return undefined;
                },
                isLive: is_window,
                close: async (windowHandle) => {
                    const socketWasConnected = Boolean(
                        session.debugSocket &&
                            session.debugSocket.readyState !== WebSocket.CLOSED,
                    );
                    const closePromise = socketWasConnected
                        ? this.waitForSocketClose(
                              session,
                              SOCKET_CLOSE_CONFIRM_MS,
                          )
                        : undefined;
                    const windowClosed = await this.requestWindowClose(
                        windowHandle,
                        `session ${session.id}`,
                    );
                    if (windowClosed) {
                        session.windowClosureObserved = true;
                    }
                    const socketClosed = closePromise
                        ? await closePromise
                        : true;
                    if (!socketClosed) {
                        this.logger.info(
                            `[miniapp] correlated hwnd closed for ${session.id}, but its debug socket is still open; checking the next recorded hwnd`,
                        );
                    }
                    return windowClosed;
                },
                onPendingHandle: (windowHandle) => {
                    session.windowHandle = windowHandle;
                },
                quietMs: WINDOW_QUIET_MS,
                timeoutMs: WINDOW_DRAIN_TIMEOUT_MS,
                pollMs: WINDOW_POLL_MS,
            });

        let drainResult = await drainSessionWindows(
            session.windowHandle,
            session.windowClosureObserved,
        );
        const identityValidated =
            session.resolvedAppId !== undefined &&
            (!session.requestedAppId ||
                session.resolvedAppId === session.requestedAppId);
        const socketStillOpen =
            session.debugSocket !== undefined &&
            session.debugSocket.readyState !== WebSocket.CLOSED;
        if (
            identityValidated &&
            session.launchStartedAt === undefined &&
            (session.windowFallbackInProgress ||
                !drainResult.observed ||
                (drainResult.closed && socketStillOpen))
        ) {
            if (!session.windowFallbackInProgress) {
                session.windowFallbackRequiresOpenSocket = socketStillOpen;
            }
            session.windowFallbackInProgress = true;
            drainResult = await drainSessionWindows(
                drainResult.pendingHandle ?? session.windowHandle,
                drainResult.observed,
                true,
                session.windowFallbackRequiresOpenSocket,
            );
            if (drainResult.closed) {
                session.windowFallbackInProgress = false;
                session.windowFallbackRequiresOpenSocket = undefined;
            }
        }
        session.windowClosureObserved ||= drainResult.observed;

        if (!drainResult.closed) {
            throw new Error(
                drainResult.observed
                    ? "miniapp window cleanup did not reach a quiet state"
                    : "miniapp window handle unavailable for close",
            );
        }
        if (
            session.debugSocket &&
            session.debugSocket.readyState !== WebSocket.CLOSED
        ) {
            throw new Error(
                "all correlated windows closed but the miniapp debug socket remained open",
            );
        }
        this.sessions.detach(session, "miniapp window closed");
    }

    private waitForSocketClose(
        session: MiniAppSession,
        timeoutMs = INTERNAL_CDP_TIMEOUT_MS,
    ) {
        return new Promise<boolean>((resolve) => {
            if (
                !session.debugSocket ||
                session.debugSocket.readyState === WebSocket.CLOSED
            ) {
                resolve(true);
                return;
            }

            let settled = false;
            const finish = (closed: boolean) => {
                if (settled) {
                    return;
                }
                settled = true;
                clearTimeout(timeout);
                session.closeWaiters.delete(waiter);
                resolve(closed);
            };
            const timeout = setTimeout(() => finish(false), timeoutMs);
            const waiter: CloseWaiter = {
                resolve: () => finish(true),
                timeout,
            };
            session.closeWaiters.add(waiter);
        });
    }

    private async requestWindowClose(
        windowHandle: number,
        description: string,
    ) {
        try {
            if (!is_window(windowHandle)) {
                return true;
            }
            close_window(windowHandle);
            this.logger.info(
                `[miniapp] requested close for ${description}: 0x${windowHandle.toString(16)}`,
            );
            const closeDeadline = Date.now() + INTERNAL_CDP_TIMEOUT_MS;
            while (Date.now() < closeDeadline) {
                if (!is_window(windowHandle)) {
                    return true;
                }
                await sleep(WINDOW_POLL_MS);
            }
            this.logger.error(
                `[miniapp] window for ${description} remained open after WM_CLOSE`,
            );
            return false;
        } catch (error) {
            try {
                if (!is_window(windowHandle)) {
                    return true;
                }
            } catch (validationError) {
                this.logger.error(
                    `[miniapp] failed to validate window for ${description}:`,
                    validationError,
                );
            }
            this.logger.error(
                `[miniapp] failed to close window for ${description}:`,
                error,
            );
            return false;
        }
    }
}
