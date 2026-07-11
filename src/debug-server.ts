import WebSocket, { RawData, WebSocketServer } from "ws";
import { isIP } from "node:net";

import { CliOptions } from "./cli";
import type { FridaServerHandle } from "./frida-server";
import { Logger } from "./logger";
import { emitMiniAppDiagnostic } from "./miniapp-diagnostics";
import { report_fatal_error } from "./process-guards";
import { close_window, is_window } from "./wechat-host";
import {
    diagnoseWin32WindowIdentity,
    inspectWin32WindowIdentity,
} from "./win32-window-diagnostics";
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

const describeSocketAddress = (address?: string) => {
    const normalized = address?.toLowerCase().split("%")[0] ?? "";
    const version = isIP(normalized);
    let kind = "other";
    if (
        normalized === "127.0.0.1" ||
        normalized.startsWith("127.") ||
        normalized === "::1" ||
        normalized.startsWith("::ffff:127.")
    ) {
        kind = "loopback";
    } else if (normalized === "0.0.0.0" || normalized === "::") {
        kind = "unspecified";
    } else if (!normalized) {
        kind = "unavailable";
    }
    return {
        family: version === 4 ? "ipv4" : version === 6 ? "ipv6" : "unknown",
        kind,
    };
};

const describeSocketEndpoint = (socket: {
    localAddress?: string;
    localPort?: number;
    remoteAddress?: string;
    remotePort?: number;
}) => ({
    localPort: socket.localPort ?? null,
    remotePort: socket.remotePort ?? null,
    localAddress: describeSocketAddress(socket.localAddress),
    remoteAddress: describeSocketAddress(socket.remoteAddress),
});

const describeTcpRow = (row: {
    family: string;
    state: number;
    localScopeId: number;
    localPort: number;
    remoteScopeId: number;
    remotePort: number;
    ownerPid: number;
} | null) =>
    row
        ? {
              family: row.family,
              state: row.state,
              localScopeId: row.localScopeId,
              localPort: row.localPort,
              remoteScopeId: row.remoteScopeId,
              remotePort: row.remotePort,
              ownerPid: row.ownerPid,
          }
        : null;

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
    fridaServer: Pick<
        FridaServerHandle,
        | "listMiniAppWindowCandidates"
        | "getMiniAppWindowCursor"
        | "getStatus"
    >,
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

    const listDebuggableSessions = () => {
        const selected = new Map<string, MiniAppSession>();
        for (const session of new Set(sessions.values())) {
            if (
                session.state !== "ready" ||
                session.debugSocket?.readyState !== WebSocket.OPEN ||
                session.appService === undefined
            ) {
                continue;
            }
            const appid = session.requestedAppId ?? session.id;
            const existing = selected.get(appid);
            if (
                !existing ||
                session.evaluationSuccesses > existing.evaluationSuccesses ||
                (session.evaluationSuccesses ===
                    existing.evaluationSuccesses &&
                    session.evaluationFailures < existing.evaluationFailures) ||
                (session.evaluationSuccesses ===
                    existing.evaluationSuccesses &&
                    session.evaluationFailures ===
                        existing.evaluationFailures &&
                    session.createdAt < existing.createdAt)
            ) {
                selected.set(appid, session);
            }
        }
        return Array.from(selected.values());
    };

    const diagnosticSession = (session: MiniAppSession) => ({
        traceId: session.traceId,
        sessionId: session.id,
        requestedAppId: session.requestedAppId ?? null,
        state: session.state,
        launchId: session.launchId ?? null,
        launchStartedAt:
            session.launchStartedAt === undefined
                ? null
                : new Date(session.launchStartedAt).toISOString(),
        launchWindowCursor: session.launchWindowCursor ?? null,
        launchAppIdConfirmed: session.launchAppIdConfirmed ?? false,
        transportPid: session.transportPid ?? null,
        hwnd:
            session.windowHandle === undefined
                ? null
                : `0x${session.windowHandle.toString(16)}`,
        identityVerified: session.windowIdentity !== undefined,
        evaluationSuccesses: session.evaluationSuccesses,
        evaluationFailures: session.evaluationFailures,
        debugSocketState: session.debugSocket?.readyState ?? null,
    });

    const getFridaTransportRelation = (
        transportPid: number | null,
        status = fridaServer.getStatus(),
    ) => {
        if (transportPid === null || status.pid === null) {
            return "unresolved" as const;
        }
        if (transportPid === status.pid) {
            return "attached-process" as const;
        }
        if (
            status.targetSelection?.selectedPid === status.pid &&
            status.targetSelection.selectedChildPids.includes(transportPid)
        ) {
            return "attached-process-child" as const;
        }
        return "outside-attached-process-family" as const;
    };

    const findAvailablePendingSpawn = () => {
        const pendingSpawnList = Array.from(pendingSpawns.values())
            .filter((pendingSpawn) => pendingSpawn.boundSessionId === undefined)
            .sort((left, right) => left.createdAt - right.createdAt);
        return pendingSpawnList.length === 1 ? pendingSpawnList[0] : undefined;
    };

    const bindPendingSpawn = (
        session: MiniAppSession,
        pendingSpawn: PendingSpawn,
        evidence: "appid" | "window",
    ) => {
        session.requestedAppId = pendingSpawn.appid;
        session.launchId = pendingSpawn.id;
        session.launchStartedAt = pendingSpawn.createdAt;
        session.launchWindowCursor = pendingSpawn.windowCursor;
        session.launchAppIdConfirmed = false;
        pendingSpawn.boundSessionId = session.id;
        session.title = pendingSpawn.appid;
        logger.info(
            `[miniapp] bound pending spawn ${pendingSpawn.appid} to ${session.id}`,
        );
        emitMiniAppDiagnostic(logger, "launch_bound", {
            ...diagnosticSession(session),
            evidence,
            launchId: pendingSpawn.id,
            appid: pendingSpawn.appid,
            windowCursor: pendingSpawn.windowCursor,
        });
    };

    const resolvePendingSpawn = (appid: string, session: MiniAppSession) => {
        const pendingSpawn = pendingSpawns.get(appid);
        if (!pendingSpawn) {
            return;
        }
        if (session.launchId !== pendingSpawn.id) {
            logger.info(
                `[miniapp] refusing to resolve pending spawn ${appid} from unrelated session ${session.id}`,
            );
            return;
        }

        clearTimeout(pendingSpawn.timeout);
        pendingSpawns.delete(appid);
        emitMiniAppDiagnostic(logger, "launch_ready", {
            ...diagnosticSession(session),
            launchId: pendingSpawn.id,
            appid,
        });
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
        emitMiniAppDiagnostic(logger, "launch_rejected", {
            source: "debug-server",
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

    const rejectSessionPendingSpawn = (
        session: MiniAppSession,
        error: Error,
    ) => {
        const pendingSpawn = session.requestedAppId
            ? pendingSpawns.get(session.requestedAppId)
            : undefined;
        if (pendingSpawn && pendingSpawn.id === session.launchId) {
            rejectPendingSpawn(pendingSpawn.appid, error);
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

    const sleep = (ms: number) =>
        new Promise<void>((resolve) => setTimeout(resolve, ms));

    const classifyWindowCandidates = (breakdown: {
        afterCursor: number;
        withinTimeWindow: number;
        windowPidMatches: number;
        enumeratedWindows: number;
        eligible: number;
    }) => {
        if (breakdown.afterCursor === 0) return "create_event_absent";
        if (breakdown.withinTimeWindow === 0)
            return "create_event_outside_launch_window";
        if (breakdown.windowPidMatches === 0)
            return "create_event_pid_mismatch";
        if (breakdown.eligible === 0) return "candidate_not_enumerated";
        if (breakdown.eligible > 1) return "multiple_exact_candidates";
        return "unique_exact_candidate";
    };

    const verifyWindowIdentityFromDiagnostic = (
        session: MiniAppSession,
        diagnostic: Awaited<
            ReturnType<typeof diagnoseWin32WindowIdentity>
        >,
        fridaStatus: ReturnType<typeof fridaServer.getStatus>,
    ) => {
        const fridaAttachedPid = fridaStatus.pid;
        const transportRelation = getFridaTransportRelation(
            diagnostic.transportPid,
            fridaStatus,
        );
        const missing: string[] = [];
        if (!session.launchId) missing.push("launch_id_missing");
        if (session.launchStartedAt === undefined)
            missing.push("launch_start_missing");
        if (session.launchWindowCursor === undefined)
            missing.push("window_cursor_missing");
        if (diagnostic.transportPid === null)
            missing.push("transport_pid_unresolved");
        if (diagnostic.transportProcessStartTime === null)
            missing.push("transport_start_time_unresolved");
        if (fridaAttachedPid === null) missing.push("frida_pid_unresolved");
        if (transportRelation === "outside-attached-process-family") {
            missing.push("transport_outside_frida_process_family");
        }
        if (missing.length > 0) {
            emitMiniAppDiagnostic(logger, "hwnd_proof_skipped", {
                ...diagnosticSession(session),
                reasons: missing,
                fridaPid: fridaAttachedPid,
                transportPid: diagnostic.transportPid,
                transportRelation,
            });
            return;
        }

        const { candidates, eligible, breakdown } = findEligibleWindowCandidates(
            diagnostic,
            session.launchWindowCursor!,
            session.launchStartedAt!,
            fridaAttachedPid!,
        );
        emitMiniAppDiagnostic(logger, "hwnd_candidates_evaluated", {
            ...diagnosticSession(session),
            reason: classifyWindowCandidates(breakdown),
            candidateCount: candidates.length,
            eligibleCount: eligible.length,
            breakdown,
            candidates: candidates.slice(0, 10).map((candidate) => ({
                sequence: candidate.sequence,
                hwnd: `0x${candidate.handle.toString(16)}`,
                pid: candidate.pid ?? null,
                tid: candidate.threadId ?? null,
                className: candidate.className ?? null,
                observedAt: new Date(candidate.createdAt).toISOString(),
            })),
            enumeratedWindowCount: diagnostic.windows.length,
            fridaPid: fridaAttachedPid,
            transportPid: diagnostic.transportPid,
            transportRelation,
        });
        if (eligible.length !== 1) {
            if (candidates.length > 0) {
                logger.info(
                    `[miniapp] HWND identity remains ambiguous for ${session.id}: ` +
                        `${candidates.length} launch-window candidates, ${eligible.length} exact socket/PID matches`,
                );
            }
            return;
        }

        const { candidate, window, expectedHwnd } = eligible[0];
        const windowProcessStartTime =
            diagnostic.windowProcessStartTimes[String(window.pid)] ?? null;
        if (windowProcessStartTime === null) {
            emitMiniAppDiagnostic(logger, "hwnd_proof_skipped", {
                ...diagnosticSession(session),
                reasons: ["window_process_start_time_unresolved"],
                hwnd: expectedHwnd,
                windowPid: window.pid,
            });
            return;
        }
        session.windowHandle = candidate.handle;
        session.windowIdentity = {
            handle: candidate.handle,
            pid: window.pid,
            tid: window.tid,
            className: window.className,
            owner: window.owner,
            root: window.root,
            rootOwner: window.rootOwner,
            launchId: session.launchId!,
            fridaObservedAt: candidate.createdAt,
            processStartTime: windowProcessStartTime,
            appIdConfirmed: session.launchAppIdConfirmed === true,
            verifiedAt: Date.now(),
        };
        logger.info(
            `[miniapp] verified HWND identity for ${session.id}: ${expectedHwnd} ` +
                `(pid=${window.pid}, tid=${window.tid}, class=${window.className})`,
        );
        emitMiniAppDiagnostic(logger, "hwnd_proof_verified", {
            ...diagnosticSession(session),
            hwnd: expectedHwnd,
            pid: window.pid,
            tid: window.tid,
            className: window.className,
            processStartTime: windowProcessStartTime,
            appIdConfirmed: session.windowIdentity!.appIdConfirmed,
        });
    };

    const findEligibleWindowCandidates = (
        diagnostic: Awaited<
            ReturnType<typeof diagnoseWin32WindowIdentity>
        >,
        windowCursor: number,
        launchStartedAt: number,
        windowOwnerPid: number,
    ) => {
        const observedBefore = Date.parse(diagnostic.observedAt);
        const afterCursor = fridaServer.listMiniAppWindowCandidates({
            afterSequence: windowCursor,
        });
        const withinTimeWindow = afterCursor.filter(
            (candidate) =>
                candidate.createdAt >= launchStartedAt &&
                (!Number.isFinite(observedBefore) ||
                    candidate.createdAt <= observedBefore),
        );
        const candidates = withinTimeWindow.filter(
            (candidate) => candidate.pid === windowOwnerPid,
        );
        const eligible = candidates.flatMap((candidate) => {
            if (candidate.threadId === undefined) {
                return [];
            }
            const expectedHwnd = `0x${candidate.handle.toString(16)}`;
            const matches = diagnostic.windows.filter(
                (window) =>
                    window.hwnd.toLowerCase() === expectedHwnd &&
                    window.pid === windowOwnerPid &&
                    window.tid === candidate.threadId,
            );
            return matches.length === 1
                ? [{ candidate, window: matches[0], expectedHwnd }]
                : [];
        });
        return {
            candidates,
            eligible,
            breakdown: {
                afterCursor: afterCursor.length,
                withinTimeWindow: withinTimeWindow.length,
                windowPidMatches: candidates.length,
                enumeratedWindows: diagnostic.windows.length,
                eligible: eligible.length,
            },
        };
    };

    const bindPendingSpawnFromWindowEvidence = (
        session: MiniAppSession,
        diagnostic: Awaited<
            ReturnType<typeof diagnoseWin32WindowIdentity>
        >,
        fridaStatus: ReturnType<typeof fridaServer.getStatus>,
    ) => {
        const fridaAttachedPid = fridaStatus.pid;
        const transportRelation = getFridaTransportRelation(
            diagnostic.transportPid,
            fridaStatus,
        );
        if (session.launchId) {
            return;
        }
        const reasons: string[] = [];
        if (session.state !== "closing")
            reasons.push("bootstrap_not_failed");
        if (session.requestedAppId !== undefined)
            reasons.push("session_already_has_appid");
        if (!session.lastError?.includes("did not return a valid appid"))
            reasons.push("failure_is_not_blank_appid");
        if (diagnostic.transportPid === null)
            reasons.push("transport_pid_unresolved");
        if (fridaAttachedPid === null) reasons.push("frida_pid_unresolved");
        if (transportRelation === "outside-attached-process-family") {
            reasons.push("transport_outside_frida_process_family");
        }
        if (reasons.length > 0) {
            emitMiniAppDiagnostic(logger, "launch_window_bind_skipped", {
                ...diagnosticSession(session),
                reasons,
                fridaPid: fridaAttachedPid,
                transportPid: diagnostic.transportPid,
                transportRelation,
            });
            return;
        }
        const pendingSpawn = findAvailablePendingSpawn();
        if (!pendingSpawn) {
            emitMiniAppDiagnostic(logger, "launch_window_bind_skipped", {
                reasons: ["no_single_unbound_pending_launch"],
                pendingLaunchCount: pendingSpawns.size,
                ...diagnosticSession(session),
            });
            return;
        }
        const { candidates, eligible, breakdown } =
            findEligibleWindowCandidates(
            diagnostic,
            pendingSpawn.windowCursor,
            pendingSpawn.createdAt,
            fridaAttachedPid!,
        );
        if (eligible.length === 1) {
            bindPendingSpawn(session, pendingSpawn, "window");
        } else {
            emitMiniAppDiagnostic(logger, "launch_window_bind_skipped", {
                ...diagnosticSession(session),
                reasons: [classifyWindowCandidates(breakdown)],
                launchId: pendingSpawn.id,
                appid: pendingSpawn.appid,
                candidateCount: candidates.length,
                eligibleCount: eligible.length,
                breakdown,
                fridaPid: fridaAttachedPid,
                transportPid: diagnostic.transportPid,
                transportRelation,
            });
        }
    };

    const logWindowIdentityDiagnostic = async (
        session: MiniAppSession,
        socket: {
            localAddress?: string;
            localPort?: number;
            remoteAddress?: string;
            remotePort?: number;
        },
        phase: "socket-connected" | "bootstrap-settled",
    ) => {
        try {
            const fridaStatus = fridaServer.getStatus();
            const fridaAttachedPid = fridaStatus.pid;
            const diagnostic = await diagnoseWin32WindowIdentity(socket, {
                additionalWindowPids:
                    fridaAttachedPid === null ? [] : [fridaAttachedPid],
            });
            const transportRelation = getFridaTransportRelation(
                diagnostic.transportPid,
                fridaStatus,
            );
            if (diagnostic.transportPid !== null) {
                session.transportPid = diagnostic.transportPid;
                touchSession(session);
            }
            bindPendingSpawnFromWindowEvidence(
                session,
                diagnostic,
                fridaStatus,
            );
            verifyWindowIdentityFromDiagnostic(
                session,
                diagnostic,
                fridaStatus,
            );
            emitMiniAppDiagnostic(logger, "identity_probe", {
                ...diagnosticSession(session),
                phase,
                reasonCodes: [
                    diagnostic.tcp.serverMatchCount === 0
                        ? "tcp_server_row_unresolved"
                        : diagnostic.tcp.serverMatchCount > 1
                          ? "tcp_server_row_ambiguous"
                          : null,
                    diagnostic.tcp.serverMatchCount === 1 &&
                    diagnostic.tcp.reverseMatchCount === 0
                        ? "tcp_reverse_row_unresolved"
                        : diagnostic.tcp.serverMatchCount === 1 &&
                            diagnostic.tcp.reverseMatchCount > 1
                          ? "tcp_reverse_row_ambiguous"
                          : diagnostic.tcp.serverMatchCount !== 1
                            ? "tcp_reverse_lookup_not_attempted"
                          : null,
                    fridaAttachedPid === null
                        ? "frida_pid_unresolved"
                        : null,
                    transportRelation === "outside-attached-process-family"
                        ? "transport_outside_frida_process_family"
                        : null,
                ].filter((reason): reason is string => reason !== null),
                endpoint: describeSocketEndpoint(diagnostic.endpoint),
                frida: {
                    pid: fridaAttachedPid,
                    phase: fridaServer.getStatus().phase,
                    hookInstalled: fridaServer.getStatus().hookInstalled,
                    transportRelation,
                },
                transportPid: diagnostic.transportPid,
                transportProcessStartTime:
                    diagnostic.transportProcessStartTime,
                windowPids: diagnostic.windowPids,
                windowProcessStartTimes:
                    diagnostic.windowProcessStartTimes,
                tcp: {
                    serverMatchCount: diagnostic.tcp.serverMatchCount,
                    serverMatchesByFamily:
                        diagnostic.tcp.serverMatchesByFamily,
                    reverseMatchCount: diagnostic.tcp.reverseMatchCount,
                    reverseMatchesByFamily:
                        diagnostic.tcp.reverseMatchesByFamily,
                    serverRow: describeTcpRow(diagnostic.tcp.serverRow),
                    reverseRow: describeTcpRow(diagnostic.tcp.reverseRow),
                },
                windows: diagnostic.windows.slice(0, 20).map((window) => ({
                    hwnd: window.hwnd,
                    pid: window.pid,
                    tid: window.tid,
                    className: window.className,
                    visible: window.visible,
                    iconic: window.iconic,
                    style: window.style,
                    exStyle: window.exStyle,
                    owner: window.owner,
                    root: window.root,
                    rootOwner: window.rootOwner,
                    rect: window.rect,
                })),
                errors: diagnostic.errors,
            });
            logger.info(
                `[miniapp] read-only window identity diagnostic (${phase}, ${session.id}): ` +
                    `fridaPid=${fridaAttachedPid ?? "none"}, ` +
                    `transportPid=${diagnostic.transportPid ?? "none"}, ` +
                    `windows=${diagnostic.windows.length}, ` +
                    `errors=${diagnostic.errors.length}`,
            );
        } catch (error) {
            const fridaStatus = fridaServer.getStatus();
            emitMiniAppDiagnostic(logger, "identity_probe_failed", {
                phase,
                error,
                endpoint: describeSocketEndpoint(socket),
                frida: {
                    pid: fridaStatus.pid,
                    phase: fridaStatus.phase,
                    hookInstalled: fridaStatus.hookInstalled,
                    targetSelection: fridaStatus.targetSelection,
                },
                ...diagnosticSession(session),
            });
            logger.error(
                `[miniapp] read-only window identity diagnostic failed (${phase}, ${session.id}):`,
                error,
            );
        }
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

            void applyForegroundState(session, appService).catch((error) => {
                logger.info(
                    `[miniapp] foreground keepalive paused for ${session.id}: ${formatErrorMessage(error)}`,
                );
            });
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
            const [resolvedContextId] = await Promise.all([
                waitForExecutionContext(
                    session,
                    appServiceSessionId,
                    frameId,
                ),
                sendInternalCommand(
                    session,
                    "Runtime.enable",
                    {},
                    appServiceSessionId,
                ),
            ]);
            contextId = resolvedContextId;
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
        const accountInfoValue = accountInfoResponse.result?.result?.value;
        const appId = accountInfoValue?.miniProgram?.appId;
        const appidValue =
            typeof appId === "string" && appId.trim().length > 0
                ? appId.trim()
                : "";
        emitMiniAppDiagnostic(logger, "appid_observed", {
            resolvedAppId: appidValue || null,
            status: appidValue ? "valid" : "blank",
            envVersion:
                accountInfoValue?.miniProgram?.envVersion ?? null,
            version: accountInfoValue?.miniProgram?.version ?? null,
            runtimeError: accountInfoValue?.__error ?? null,
            ...diagnosticSession(session),
        });
        logger.info(
            `[miniapp] account info for ${session.id}: ` +
                `appid=${appidValue || "<blank>"}, ` +
                `env=${accountInfoValue?.miniProgram?.envVersion ?? "unknown"}, ` +
                `version=${accountInfoValue?.miniProgram?.version ?? "unknown"}`,
        );
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
            let result;
            try {
                result = await sendEvaluate(false);
            } catch (error) {
                if (!isRecoverableAppContextError(error)) {
                    throw error;
                }

                logger.info(
                    `[miniapp] refreshing appContext for ${session.id} after evaluate failure`,
                );
                result = await sendEvaluate(true);
            }
            session.evaluationSuccesses += 1;
            session.lastEvaluationSucceededAt = Date.now();
            touchSession(session);
            emitMiniAppDiagnostic(logger, "attachment_evaluate_succeeded", {
                ...diagnosticSession(session),
            });
            return result;
        } catch (error) {
            session.evaluationFailures += 1;
            session.lastEvaluationFailedAt = Date.now();
            touchSession(session);
            emitMiniAppDiagnostic(logger, "attachment_evaluate_failed", {
                error,
                ...diagnosticSession(session),
            });
            throw error;
        }
    };

    const rekeySessionByAppId = (session: MiniAppSession, appid: string) => {
        if (session.id === appid) {
            if (!sessions.has(appid)) {
                sessions.set(appid, session);
            }
            return "canonical" as const;
        }

        const existing = sessions.get(appid);
        if (existing && existing !== session) {
            const existingUsable =
                existing.state === "ready" &&
                existing.debugSocket?.readyState === WebSocket.OPEN &&
                existing.appService !== undefined;
            if (existingUsable) {
                logger.info(
                    `[miniapp] alternate attachment ready for ${appid}: keeping canonical ${existing.traceId}, candidate ${session.traceId}`,
                );
                emitMiniAppDiagnostic(logger, "attachment_candidate_ready", {
                    appid,
                    disposition: "alternate",
                    canonicalTraceId: existing.traceId,
                    candidateTraceId: session.traceId,
                    sameTransportPid:
                        existing.transportPid !== undefined &&
                        existing.transportPid === session.transportPid,
                    ...diagnosticSession(session),
                });
                return "alternate" as const;
            }

            if (
                existing.transportPid !== undefined &&
                existing.transportPid === session.transportPid
            ) {
                session.launchId ??= existing.launchId;
                session.launchStartedAt ??= existing.launchStartedAt;
                session.launchWindowCursor ??= existing.launchWindowCursor;
                session.launchAppIdConfirmed ||= existing.launchAppIdConfirmed;
                session.windowHandle ??= existing.windowHandle;
                session.windowIdentity ??= existing.windowIdentity;
            }
            sessions.delete(appid);
            existing.state = "closing";
            existing.lastError = "superseded by a working attachment";
            stopForegroundKeepAlive(existing);
            touchSession(existing);
            logger.info(
                `[miniapp] replacing stale attachment for ${appid}: ${existing.traceId} -> ${session.traceId}`,
            );
            emitMiniAppDiagnostic(logger, "attachment_candidate_ready", {
                appid,
                disposition: "replaced-stale-canonical",
                canonicalTraceId: existing.traceId,
                candidateTraceId: session.traceId,
                ...diagnosticSession(session),
            });
        }

        const previousId = session.id;
        sessions.delete(previousId);
        session.id = appid;
        sessions.set(appid, session);
        return "canonical" as const;
    };

    const promoteSessionAttachment = (
        appid: string,
        candidate: MiniAppSession,
    ) => {
        const canonical = sessions.get(appid);
        const candidateSocket = candidate.debugSocket;
        if (
            !canonical ||
            canonical === candidate ||
            candidate.state !== "ready" ||
            !candidate.appService ||
            !candidateSocket ||
            candidateSocket.readyState !== WebSocket.OPEN
        ) {
            return canonical ?? candidate;
        }

        const oldSocket = canonical.debugSocket;
        const oldDevtoolsSocket = canonical.devtoolsSocket;
        stopForegroundKeepAlive(canonical);
        stopForegroundKeepAlive(candidate);
        rejectPendingWork(
            canonical,
            "miniapp attachment superseded by a successful candidate",
        );

        canonical.debugSocket = candidateSocket;
        canonical.appService = candidate.appService;
        canonical.transportPid = candidate.transportPid;
        canonical.state = "ready";
        canonical.lastError = undefined;
        canonical.messageCounter = Math.max(
            canonical.messageCounter,
            candidate.messageCounter,
        );
        canonical.internalCommandCounter = Math.max(
            canonical.internalCommandCounter,
            candidate.internalCommandCounter,
        );
        canonical.evaluationSuccesses += candidate.evaluationSuccesses;
        canonical.evaluationFailures += candidate.evaluationFailures;
        canonical.lastEvaluationSucceededAt =
            candidate.lastEvaluationSucceededAt;
        canonical.lastEvaluationFailedAt = candidate.lastEvaluationFailedAt;
        canonical.windowHandle ??= candidate.windowHandle;
        canonical.windowIdentity ??= candidate.windowIdentity;
        canonical.launchId ??= candidate.launchId;
        canonical.launchStartedAt ??= candidate.launchStartedAt;
        canonical.launchWindowCursor ??= candidate.launchWindowCursor;
        canonical.launchAppIdConfirmed ||= candidate.launchAppIdConfirmed;

        if (!canonical.devtoolsSocket && candidate.devtoolsSocket) {
            canonical.devtoolsSocket = candidate.devtoolsSocket;
            canonical.attached = candidate.attached;
        } else if (
            candidate.devtoolsSocket &&
            candidate.devtoolsSocket !== canonical.devtoolsSocket
        ) {
            closeWebSocket(
                candidate.devtoolsSocket,
                1001,
                "alternate miniapp attachment superseded",
            );
        }

        debugSocketSessions.set(candidateSocket, canonical);
        candidate.debugSocket = undefined;
        candidate.devtoolsSocket = undefined;
        candidate.appService = undefined;
        candidate.attached = false;
        candidate.state = "closing";
        candidate.lastError = "promoted into canonical attachment";
        removeSession(candidate);
        touchSession(candidate);
        touchSession(canonical);
        startForegroundKeepAlive(canonical);

        if (oldSocket && oldSocket !== candidateSocket) {
            debugSocketSessions.delete(oldSocket);
            closeWebSocket(
                oldSocket,
                1001,
                "superseded by a working miniapp attachment",
            );
        }
        if (
            oldDevtoolsSocket &&
            canonical.devtoolsSocket !== oldDevtoolsSocket
        ) {
            closeWebSocket(
                oldDevtoolsSocket,
                1001,
                "miniapp attachment changed",
            );
        }

        logger.info(
            `[miniapp] promoted successful attachment for ${appid}: ${candidate.traceId} -> ${canonical.traceId}`,
        );
        emitMiniAppDiagnostic(logger, "attachment_promoted", {
            appid,
            canonicalTraceId: canonical.traceId,
            candidateTraceId: candidate.traceId,
            replacedSocket: oldSocket !== undefined,
            ...diagnosticSession(canonical),
        });
        return canonical;
    };

    const bootstrapSession = async (session: MiniAppSession) => {
        const bootstrapStartedAt = Date.now();
        emitMiniAppDiagnostic(logger, "bootstrap_started", {
            ...diagnosticSession(session),
        });
        try {
            const appid = await resolveSessionAppId(session);
            if (session.closeInProgress) {
                throw new Error("bootstrap cancelled by explicit close");
            }
            if (!session.launchId) {
                const matchingPendingSpawn = pendingSpawns.get(appid);
                if (
                    matchingPendingSpawn &&
                    matchingPendingSpawn.boundSessionId === undefined
                ) {
                    bindPendingSpawn(session, matchingPendingSpawn, "appid");
                }
            }
            const expectedAppId = session.requestedAppId;
            const launchMismatch =
                expectedAppId !== undefined && expectedAppId !== appid;
            if (launchMismatch) {
                const mismatchMessage =
                    `pending launch expected ${expectedAppId}, but the socket resolved to ${appid}`;
                rejectPendingSpawn(expectedAppId, new Error(mismatchMessage));
                session.windowHandle = undefined;
                session.windowIdentity = undefined;
                session.launchId = undefined;
                session.launchStartedAt = undefined;
                session.launchWindowCursor = undefined;
                session.launchAppIdConfirmed = false;
                logger.error(`[miniapp] ${mismatchMessage}; HWND candidate discarded`);
                emitMiniAppDiagnostic(logger, "appid_mismatch", {
                    expectedAppId,
                    resolvedAppId: appid,
                    ...diagnosticSession(session),
                });
            }
            if (appid) {
                session.title = appid;
                session.requestedAppId = appid;
                rekeySessionByAppId(session, appid);
            }
            if (!launchMismatch) {
                session.launchAppIdConfirmed = true;
                if (session.windowIdentity) {
                    session.windowIdentity.appIdConfirmed = true;
                }
            }
            session.state = "ready";
            session.lastError = undefined;
            startForegroundKeepAlive(session);
            touchSession(session);
            if (appid && !launchMismatch) {
                resolvePendingSpawn(appid, session);
            }
            logger.info(`[miniapp] miniapp ready: ${session.id}`);
            emitMiniAppDiagnostic(logger, "bootstrap_ready", {
                resolvedAppId: appid,
                durationMs: Date.now() - bootstrapStartedAt,
                ...diagnosticSession(session),
            });
        } catch (error) {
            const errorMessage = formatErrorMessage(error);
            const closeMessage = `miniapp bootstrap failed: ${errorMessage}`;
            if (session.closeInProgress) {
                rejectSessionPendingSpawn(session, new Error(closeMessage));
                logger.info(
                    `[miniapp] bootstrap stopped for ${session.id} because explicit close is in progress`,
                );
                emitMiniAppDiagnostic(logger, "bootstrap_cancelled", {
                    durationMs: Date.now() - bootstrapStartedAt,
                    error,
                    ...diagnosticSession(session),
                });
                return;
            }
            session.state = "closing";
            session.lastError = closeMessage;
            touchSession(session);
            stopForegroundKeepAlive(session);
            logger.error(`[miniapp] bootstrap failed for ${session.id}:`, error);
            emitMiniAppDiagnostic(logger, "bootstrap_failed", {
                durationMs: Date.now() - bootstrapStartedAt,
                error,
                automaticCloseSkipped: true,
                ...diagnosticSession(session),
            });
            rejectSessionPendingSpawn(session, new Error(closeMessage));
            logger.info(
                `[miniapp] automatic close skipped for ${session.id}; use the explicit despawn endpoint if closure is required`,
            );
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

    const validateWindowForClose = (
        session: MiniAppSession,
        allowLaunchCorrelated: boolean,
    ) => {
        const identity = session.windowIdentity;
        if (!identity || identity.launchId !== session.launchId) {
            emitMiniAppDiagnostic(logger, "close_revalidation", {
                outcome: "rejected",
                reason: "close_identity_missing",
                allowLaunchCorrelated,
                ...diagnosticSession(session),
            });
            throw new Error(
                "miniapp window identity unavailable; refusing to close an unverified window",
            );
        }
        if (!identity.appIdConfirmed && !allowLaunchCorrelated) {
            emitMiniAppDiagnostic(logger, "close_revalidation", {
                outcome: "rejected",
                reason: "close_appid_unconfirmed",
                expected: {
                    hwnd: `0x${identity.handle.toString(16)}`,
                    pid: identity.pid,
                    tid: identity.tid,
                    className: identity.className,
                },
                allowLaunchCorrelated,
                ...diagnosticSession(session),
            });
            throw new Error(
                "miniapp appid was not confirmed; retry explicit despawn with allowLaunchCorrelated=true to close the launch-correlated HWND",
            );
        }

        const inspection = inspectWin32WindowIdentity(
            identity.handle,
            identity.pid,
        );
        if (!inspection.windowCheckCompleted) {
            emitMiniAppDiagnostic(logger, "close_revalidation", {
                outcome: "rejected",
                reason: "close_inspection_failed",
                errors: inspection.errors,
                ...diagnosticSession(session),
            });
            throw new Error(
                `miniapp window revalidation failed: ${inspection.errors.join("; ") || "unknown Win32 error"}`,
            );
        }
        if (!inspection.windowExists) {
            if (
                session.debugSocket &&
                session.debugSocket.readyState === WebSocket.OPEN
            ) {
                emitMiniAppDiagnostic(logger, "close_revalidation", {
                    outcome: "rejected",
                    reason: "close_hwnd_gone_socket_connected",
                    inspection,
                    ...diagnosticSession(session),
                });
                throw new Error(
                    "verified miniapp HWND disappeared while its runtime socket is still connected; refusing detach-only cleanup",
                );
            }
            emitMiniAppDiagnostic(logger, "close_revalidation", {
                outcome: "already_gone",
                reason: "close_hwnd_already_gone",
                inspection,
                ...diagnosticSession(session),
            });
            return { identity, alreadyGone: true } as const;
        }
        const window = inspection.snapshot;
        const sameHandle = `0x${identity.handle.toString(16)}`;
        const mismatchFields = !window
            ? ["snapshot"]
            : [
                  inspection.processStartTime !== identity.processStartTime
                      ? "processStartTime"
                      : null,
                  window.hwnd.toLowerCase() !== sameHandle ? "hwnd" : null,
                  window.pid !== identity.pid ? "pid" : null,
                  window.tid !== identity.tid ? "tid" : null,
                  window.className !== identity.className
                      ? "className"
                      : null,
                  window.owner !== identity.owner ? "owner" : null,
                  window.root !== identity.root ? "root" : null,
                  window.rootOwner !== identity.rootOwner
                      ? "rootOwner"
                      : null,
              ].filter((field): field is string => field !== null);
        if (mismatchFields.length > 0) {
            emitMiniAppDiagnostic(logger, "close_revalidation", {
                outcome: "rejected",
                reason: "close_identity_changed",
                mismatchFields,
                expected: {
                    hwnd: sameHandle,
                    pid: identity.pid,
                    tid: identity.tid,
                    className: identity.className,
                    owner: identity.owner,
                    root: identity.root,
                    rootOwner: identity.rootOwner,
                    processStartTime: identity.processStartTime,
                },
                actual: window
                    ? {
                          hwnd: window.hwnd,
                          pid: window.pid,
                          tid: window.tid,
                          className: window.className,
                          owner: window.owner,
                          root: window.root,
                          rootOwner: window.rootOwner,
                          processStartTime: inspection.processStartTime,
                      }
                    : null,
                errors: inspection.errors,
                ...diagnosticSession(session),
            });
            throw new Error(
                "miniapp window identity changed; refusing to close a recycled or unrelated HWND",
            );
        }

        emitMiniAppDiagnostic(logger, "close_revalidation", {
            ...diagnosticSession(session),
            outcome: "verified",
            reason: "close_identity_verified",
            hwnd: sameHandle,
            pid: identity.pid,
            tid: identity.tid,
            appIdConfirmed: identity.appIdConfirmed,
            allowLaunchCorrelated,
        });

        return { identity, alreadyGone: false } as const;
    };

    const closeVerifiedWindow = async (
        session: MiniAppSession,
        identity: MiniAppSession["windowIdentity"] & {},
    ) => {
        const closeStartedAt = Date.now();
        try {
            close_window(identity.handle, {
                pid: identity.pid,
                tid: identity.tid,
            });
            emitMiniAppDiagnostic(logger, "close_dispatch", {
                ...diagnosticSession(session),
                outcome: "posted",
                hwnd: `0x${identity.handle.toString(16)}`,
                pid: identity.pid,
                tid: identity.tid,
            });
        } catch (error) {
            emitMiniAppDiagnostic(logger, "close_dispatch", {
                ...diagnosticSession(session),
                outcome: "post_failed",
                hwnd: `0x${identity.handle.toString(16)}`,
                error,
            });
            throw error;
        }
        const deadline = Date.now() + INTERNAL_CDP_TIMEOUT_MS;
        while (Date.now() < deadline) {
            if (!is_window(identity.handle)) {
                emitMiniAppDiagnostic(logger, "close_dispatch", {
                    ...diagnosticSession(session),
                    outcome: "closed",
                    hwnd: `0x${identity.handle.toString(16)}`,
                    elapsedMs: Date.now() - closeStartedAt,
                });
                return;
            }
            await sleep(MINIAPP_WINDOW_WAIT_INTERVAL_MS);
        }

        emitMiniAppDiagnostic(logger, "close_dispatch", {
            ...diagnosticSession(session),
            outcome: "timeout",
            reason: "wm_close_timeout",
            hwnd: `0x${identity.handle.toString(16)}`,
            elapsedMs: Date.now() - closeStartedAt,
        });

        throw new Error(
            `miniapp window did not close: 0x${identity.handle.toString(16)}`,
        );
    };

    const killMiniApp = async (
        session: MiniAppSession,
        reason: string,
        options: { allowLaunchCorrelated?: boolean } = {},
    ) => {
        const previousState = session.state;
        const previousError = session.lastError;

        try {
            const validated = validateWindowForClose(
                session,
                options.allowLaunchCorrelated === true,
            );
            if (validated.alreadyGone) {
                detachSession(session, reason);
                return {
                    closed: false,
                    alreadyGone: true,
                    cleanupComplete: true,
                    forced: false,
                    launchCorrelatedClose:
                        !validated.identity.appIdConfirmed,
                    error: null,
                };
            }

            session.closeInProgress = true;
            session.state = "closing";
            session.lastError = reason;
            touchSession(session);
            stopForegroundKeepAlive(session);
            await closeVerifiedWindow(session, validated.identity);
            detachSession(session, reason);
            return {
                closed: true,
                alreadyGone: false,
                cleanupComplete: true,
                forced: false,
                launchCorrelatedClose:
                    !validated.identity.appIdConfirmed,
                error: null,
            };
        } catch (error) {
            logger.error(
                `[miniapp] window close failed for ${session.id}; keeping session attached for retry:`,
                error,
            );
            session.closeInProgress = false;
            if (previousState === "ready") {
                session.state = previousState;
                session.lastError = previousError;
                startForegroundKeepAlive(session);
            } else if (session.state !== "closing") {
                session.state = previousState;
                session.lastError = previousError;
            }
            touchSession(session);
            return {
                closed: false,
                alreadyGone: false,
                cleanupComplete: false,
                forced: false,
                launchCorrelatedClose: false,
                error: `miniapp close failed: ${formatErrorMessage(error)}`,
            };
        }
    };

    wss.on("connection", (ws: WebSocket, request) => {
        const socketEndpoint = {
            localAddress: request.socket.localAddress,
            localPort: request.socket.localPort,
            remoteAddress: request.socket.remoteAddress,
            remotePort: request.socket.remotePort,
        };
        const session = createSession();
        session.debugSocket = ws;
        sessions.set(session.id, session);
        debugSocketSessions.set(ws, session);
        logger.info(`[miniapp] miniapp client connected: ${session.id}`);
        emitMiniAppDiagnostic(logger, "socket_connected", {
            endpoint: describeSocketEndpoint(socketEndpoint),
            pendingLaunchCount: pendingSpawns.size,
            frida: fridaServer.getStatus(),
            ...diagnosticSession(session),
        });
        void logWindowIdentityDiagnostic(
            session,
            socketEndpoint,
            "socket-connected",
        );

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
        ws.on("close", (code, reason) => {
            const currentSession = debugSocketSessions.get(ws);
            if (!currentSession) {
                return;
            }

            const proofStage = currentSession.windowIdentity?.appIdConfirmed
                ? "appid_confirmed"
                : currentSession.windowIdentity
                  ? "hwnd_verified"
                  : currentSession.transportPid !== undefined
                    ? "transport_identified"
                    : "socket_only";
            emitMiniAppDiagnostic(logger, "socket_disconnected", {
                code,
                reasonBytes: reason.byteLength,
                connectedMs: Date.now() - currentSession.createdAt,
                stateBefore: currentSession.state,
                proofStage,
                ...diagnosticSession(currentSession),
            });

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
            let retainedForExplicitClose =
                currentSession.launchStartedAt !== undefined;
            if (currentSession.windowHandle !== undefined) {
                try {
                    retainedForExplicitClose ||=
                        is_window(currentSession.windowHandle);
                } catch (error) {
                    logger.error(
                        `[miniapp] failed to validate cached hwnd for ${currentSession.id}:`,
                        error,
                    );
                }
            }
            if (!retainedForExplicitClose) {
                removeSession(currentSession);
            }
            debugSocketSessions.delete(ws);
            logger.info(
                retainedForExplicitClose
                    ? `[miniapp] miniapp client disconnected: ${currentSession.id}; retaining cached hwnd for explicit close`
                    : `[miniapp] miniapp client disconnected: ${currentSession.id}`,
            );
            emitMiniAppDiagnostic(logger, "session_after_disconnect", {
                retainedForExplicitClose,
                ...diagnosticSession(currentSession),
            });
        });

        void bootstrapSession(session).finally(() =>
            logWindowIdentityDiagnostic(
                session,
                socketEndpoint,
                "bootstrap-settled",
            ),
        );
    });

    return {
        listDebuggableSessions,
        killMiniApp,
        evaluateInAppContext,
        promoteSessionAttachment,
        sendMiniAppCdpMessage,
    };
};
