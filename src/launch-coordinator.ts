import WebSocket from "ws";

import { MiniAppSession } from "./session";

type LaunchWaiter = {
    resolve: (session: MiniAppSession) => void;
    reject: (error: Error) => void;
};

export type LaunchPhase =
    | "waiting-for-hook"
    | "dispatching"
    | "waiting-for-connection"
    | "bootstrapping"
    | "cleaning-mismatch"
    | "cleaning"
    | "blocked";

export type LaunchAttempt = {
    id: number;
    appid: string;
    phase: LaunchPhase;
    createdAt: number;
    phaseStartedAt: number;
    dispatchStartedAt?: number;
    dispatchCount?: number;
    windowHandle?: number;
    windowClosureObserved?: boolean;
    timeout?: NodeJS.Timeout;
    session?: MiniAppSession;
    launchPromise?: Promise<void>;
    redispatch?: () => Promise<void>;
    failurePromise?: Promise<void>;
    cancelRequested?: boolean;
    lastError?: string;
    identityMismatch?: boolean;
    lateResolvedSession?: MiniAppSession;
    cleanupSessions?: Set<MiniAppSession>;
    waiters: Set<LaunchWaiter>;
    result?:
        | { state: "ready"; session: MiniAppSession }
        | { state: "failed"; error: Error };
};

export type LaunchAttemptResult =
    | { attempt: LaunchAttempt; created: true }
    | { attempt: LaunchAttempt; created: false };

export type LaunchScheduler = {
    setTimeout: (callback: () => void, timeoutMs: number) => NodeJS.Timeout;
    clearTimeout: (timeout: NodeJS.Timeout) => void;
};

const defaultScheduler: LaunchScheduler = {
    setTimeout: (callback, timeoutMs) => setTimeout(callback, timeoutMs),
    clearTimeout: (timeout) => clearTimeout(timeout),
};

const allowedPhaseTransitions: Record<LaunchPhase, ReadonlySet<LaunchPhase>> = {
    "waiting-for-hook": new Set([
        "waiting-for-hook",
        "dispatching",
        "bootstrapping",
    ]),
    dispatching: new Set(["dispatching", "waiting-for-connection", "bootstrapping"]),
    "waiting-for-connection": new Set([
        "waiting-for-connection",
        "dispatching",
        "bootstrapping",
    ]),
    bootstrapping: new Set(["bootstrapping"]),
    "cleaning-mismatch": new Set(),
    cleaning: new Set(),
    blocked: new Set(),
};

export class LaunchBusyError extends Error {
    readonly activeAppId: string;

    constructor(activeAppId: string) {
        super(`another miniapp is already launching: ${activeAppId}`);
        this.name = "LaunchBusyError";
        this.activeAppId = activeAppId;
    }
}

export class LaunchBlockedError extends Error {
    readonly activeAppId: string;

    constructor(activeAppId: string, detail?: string) {
        super(
            `previous launch cleanup is incomplete for ${activeAppId}` +
                (detail ? `: ${detail}` : "") +
                "; despawn it before retrying",
        );
        this.name = "LaunchBlockedError";
        this.activeAppId = activeAppId;
    }
}

export class MiniAppLaunchError extends Error {
    constructor(
        message: string,
        readonly statusCode: number,
    ) {
        super(message);
        this.name = "MiniAppLaunchError";
    }
}

const formatError = (error: unknown) =>
    error instanceof Error ? error : new Error(String(error));

const isReusableSession = (session: MiniAppSession | undefined) =>
    session !== undefined &&
    session.state !== "closing" &&
    session.debugSocket?.readyState === WebSocket.OPEN;

export class MiniAppLaunchCoordinator {
    private readonly attempts = new Map<string, LaunchAttempt>();
    private activeAttempt?: LaunchAttempt;
    private nextAttemptId = 0;

    constructor(private readonly scheduler: LaunchScheduler = defaultScheduler) {}

    get(appid: string) {
        return this.attempts.get(appid);
    }

    getActive() {
        return this.activeAttempt;
    }

    isCleanupSession(session: MiniAppSession) {
        return this.activeAttempt?.cleanupSessions?.has(session) ?? false;
    }

    isSessionQuarantined(session: MiniAppSession) {
        const attempt = this.activeAttempt;
        if (!attempt) {
            return false;
        }
        return (
            attempt.cleanupSessions?.has(session) === true ||
            ((attempt.phase === "cleaning" ||
                attempt.phase === "cleaning-mismatch" ||
                attempt.phase === "blocked") &&
                (attempt.session === session ||
                    attempt.lateResolvedSession === session))
        );
    }

    getOwningAttempt(session: MiniAppSession) {
        const attempt = this.activeAttempt;
        if (
            attempt &&
            (attempt.session === session ||
                attempt.cleanupSessions?.has(session) === true ||
                attempt.lateResolvedSession === session)
        ) {
            return attempt;
        }
        return undefined;
    }

    requestCancellation(attempt: LaunchAttempt) {
        if (
            this.attempts.get(attempt.appid) !== attempt ||
            this.activeAttempt !== attempt
        ) {
            return false;
        }
        attempt.cancelRequested = true;
        if (attempt.lateResolvedSession) {
            this.addCleanupSession(attempt, attempt.lateResolvedSession);
        }
        return true;
    }

    trackCancelledSession(session: MiniAppSession) {
        const attempt = this.activeAttempt;
        if (
            !attempt ||
            !attempt.cancelRequested ||
            this.attempts.get(attempt.appid) !== attempt
        ) {
            return undefined;
        }
        session.launchStartedAt =
            attempt.dispatchStartedAt ?? attempt.createdAt;
        session.windowHandle ??= attempt.windowHandle;
        session.windowClosureObserved ||= attempt.windowClosureObserved;
        this.addCleanupSession(attempt, session);
        return attempt;
    }

    isCurrent(attempt: LaunchAttempt) {
        return (
            this.attempts.get(attempt.appid) === attempt &&
            this.activeAttempt === attempt &&
            attempt.result === undefined
        );
    }

    createOrJoin(appid: string): LaunchAttemptResult {
        const existing = this.attempts.get(appid);
        if (existing?.phase === "blocked") {
            throw new LaunchBlockedError(appid, existing.lastError);
        }
        if (existing && existing.result === undefined) {
            return { attempt: existing, created: false };
        }

        if (this.activeAttempt?.phase === "blocked") {
            throw new LaunchBlockedError(
                this.activeAttempt.appid,
                this.activeAttempt.lastError,
            );
        }
        if (this.activeAttempt && this.activeAttempt.result === undefined) {
            throw new LaunchBusyError(this.activeAttempt.appid);
        }

        const now = Date.now();
        const attempt: LaunchAttempt = {
            id: ++this.nextAttemptId,
            appid,
            phase: "waiting-for-hook",
            createdAt: now,
            phaseStartedAt: now,
            waiters: new Set(),
        };
        this.attempts.set(appid, attempt);
        this.activeAttempt = attempt;
        return { attempt, created: true };
    }

    setPhase(
        attempt: LaunchAttempt,
        phase: LaunchPhase,
        timeoutMs?: number,
        onTimeout?: (attempt: LaunchAttempt) => void,
    ) {
        if (!this.isCurrent(attempt)) {
            return false;
        }
        if (!allowedPhaseTransitions[attempt.phase].has(phase)) {
            return false;
        }

        this.clearTimer(attempt);
        attempt.phase = phase;
        attempt.phaseStartedAt = Date.now();
        if (phase === "dispatching") {
            attempt.dispatchStartedAt = attempt.phaseStartedAt;
        }

        if (timeoutMs !== undefined && onTimeout) {
            const timeout = this.scheduler.setTimeout(() => {
                if (this.isCurrent(attempt) && attempt.timeout === timeout) {
                    attempt.timeout = undefined;
                    onTimeout(attempt);
                }
            }, timeoutMs);
            timeout.unref();
            attempt.timeout = timeout;
        }
        return true;
    }

    claimActiveSession(session: MiniAppSession) {
        const attempt = this.activeAttempt;
        if (
            !attempt ||
            !this.isCurrent(attempt) ||
            (attempt.phase !== "dispatching" &&
                attempt.phase !== "waiting-for-connection")
        ) {
            return undefined;
        }

        this.bindSession(attempt, session);
        return attempt;
    }

    bindSession(attempt: LaunchAttempt, session: MiniAppSession) {
        if (!this.isCurrent(attempt)) {
            return false;
        }
        attempt.session = session;
        session.launchAttemptId = attempt.id;
        session.requestedAppId = attempt.appid;
        session.launchStartedAt = attempt.dispatchStartedAt ?? attempt.createdAt;
        session.windowHandle ??= attempt.windowHandle;
        return true;
    }

    adoptResolvedSession(session: MiniAppSession, resolvedAppId: string) {
        if (!isReusableSession(session)) {
            return undefined;
        }
        const attempt = this.activeAttempt;
        if (
            attempt &&
            attempt.cancelRequested &&
            this.attempts.get(attempt.appid) === attempt &&
            attempt.appid === resolvedAppId
        ) {
            this.addCleanupSession(attempt, session);
            return undefined;
        }
        if (
            attempt &&
            this.attempts.get(attempt.appid) === attempt &&
            attempt.phase === "blocked" &&
            !attempt.identityMismatch &&
            (attempt.cleanupSessions?.size ?? 0) === 0 &&
            attempt.appid === resolvedAppId
        ) {
            attempt.result = undefined;
            attempt.failurePromise = undefined;
            attempt.launchPromise = Promise.resolve();
            attempt.lastError = undefined;
            attempt.phase = "bootstrapping";
            attempt.phaseStartedAt = Date.now();
        }
        if (
            attempt &&
            this.attempts.get(attempt.appid) === attempt &&
            (attempt.phase === "cleaning" ||
                attempt.phase === "cleaning-mismatch") &&
            attempt.appid === resolvedAppId
        ) {
            this.recordLateResolvedSession(session, resolvedAppId);
            return undefined;
        }
        if (
            !attempt ||
            !this.isCurrent(attempt) ||
            attempt.phase === "cleaning" ||
            attempt.phase === "cleaning-mismatch" ||
            attempt.appid !== resolvedAppId
        ) {
            return undefined;
        }

        const displacedSession = attempt.session;
        if (displacedSession && displacedSession !== session) {
            this.addCleanupSession(attempt, displacedSession);
            displacedSession.launchAttemptId = undefined;
            if (displacedSession.resolvedAppId === undefined) {
                displacedSession.requestedAppId = undefined;
            }
        }
        this.bindSession(attempt, session);
        return { attempt, displacedSession };
    }

    recordLateResolvedSession(
        session: MiniAppSession,
        resolvedAppId: string,
    ) {
        const attempt = this.activeAttempt;
        if (
            attempt &&
            attempt.cancelRequested &&
            this.attempts.get(attempt.appid) === attempt &&
            attempt.appid === resolvedAppId &&
            isReusableSession(session)
        ) {
            this.addCleanupSession(attempt, session);
            return false;
        }
        if (
            attempt &&
            this.attempts.get(attempt.appid) === attempt &&
            attempt.phase === "blocked" &&
            attempt.appid === resolvedAppId &&
            session.state === "ready" &&
            isReusableSession(session)
        ) {
            if (
                !attempt.identityMismatch &&
                (attempt.cleanupSessions?.size ?? 0) === 0 &&
                (!attempt.session || attempt.session === session)
            ) {
                attempt.result = undefined;
                attempt.failurePromise = undefined;
                attempt.launchPromise = Promise.resolve();
                attempt.lastError = undefined;
                attempt.phase = "bootstrapping";
                attempt.phaseStartedAt = Date.now();
                this.bindSession(attempt, session);
                return this.resolve(attempt, session);
            }
            this.addCleanupSession(attempt, session);
            return false;
        }
        if (
            !attempt ||
            this.attempts.get(attempt.appid) !== attempt ||
            (attempt.phase !== "cleaning" &&
                attempt.phase !== "cleaning-mismatch") ||
            attempt.appid !== resolvedAppId ||
            !isReusableSession(session)
        ) {
            return false;
        }

        const currentLateSession = attempt.lateResolvedSession;
        if (
            !isReusableSession(currentLateSession) ||
            (session.state === "ready" &&
                currentLateSession?.state !== "ready")
        ) {
            attempt.lateResolvedSession = session;
        }
        return true;
    }

    releaseMismatchedSession(
        attempt: LaunchAttempt,
        session: MiniAppSession,
    ) {
        if (!this.isCurrent(attempt) || attempt.session !== session) {
            return false;
        }
        attempt.session = undefined;
        attempt.identityMismatch = true;
        this.addCleanupSession(attempt, session);
        this.clearTimer(attempt);
        attempt.phase = "cleaning-mismatch";
        attempt.phaseStartedAt = Date.now();
        session.launchAttemptId = undefined;
        session.requestedAppId = undefined;
        return true;
    }

    addCleanupSession(attempt: LaunchAttempt, session: MiniAppSession) {
        if (
            this.attempts.get(attempt.appid) !== attempt ||
            this.activeAttempt !== attempt
        ) {
            return false;
        }
        attempt.cleanupSessions ??= new Set();
        attempt.cleanupSessions.add(session);
        return true;
    }

    completeCleanupSession(
        attempt: LaunchAttempt,
        session: MiniAppSession,
    ) {
        attempt.cleanupSessions?.delete(session);
    }

    completeMismatchedSessionCleanup(
        attempt: LaunchAttempt,
        cleanedSession: MiniAppSession,
    ) {
        if (
            this.attempts.get(attempt.appid) !== attempt ||
            this.activeAttempt !== attempt ||
            attempt.result !== undefined ||
            attempt.phase !== "cleaning-mismatch" ||
            attempt.session !== undefined
        ) {
            return undefined;
        }
        this.completeCleanupSession(attempt, cleanedSession);
        if (attempt.cancelRequested) {
            const hasRemainingOwners =
                (attempt.cleanupSessions?.size ?? 0) > 0 ||
                attempt.session !== undefined ||
                attempt.lateResolvedSession !== undefined;
            this.settleRejected(
                attempt,
                new MiniAppLaunchError(
                    "miniapp launch cancelled during mismatch cleanup",
                    409,
                ),
                !hasRemainingOwners,
            );
            return undefined;
        }
        if (attempt.cleanupSessions && attempt.cleanupSessions.size > 0) {
            return undefined;
        }
        attempt.identityMismatch = false;
        attempt.phase = "waiting-for-connection";
        attempt.phaseStartedAt = Date.now();
        const lateSession = attempt.lateResolvedSession;
        if (
            !lateSession ||
            !isReusableSession(lateSession)
        ) {
            attempt.lateResolvedSession = undefined;
            return "waiting" as const;
        }
        attempt.lateResolvedSession = undefined;
        this.bindSession(attempt, lateSession);
        if (lateSession.state === "ready") {
            this.resolve(attempt, lateSession);
            return "resolved" as const;
        }
        attempt.phase = "bootstrapping";
        attempt.phaseStartedAt = Date.now();
        return "adopted" as const;
    }

    getSessionAttempt(session: MiniAppSession) {
        const appid = session.requestedAppId;
        if (!appid || session.launchAttemptId === undefined) {
            return undefined;
        }
        const attempt = this.attempts.get(appid);
        return attempt &&
            attempt.id === session.launchAttemptId &&
            attempt.session === session &&
            this.isCurrent(attempt)
            ? attempt
            : undefined;
    }

    waitForReady(attempt: LaunchAttempt) {
        if (attempt.result?.state === "ready") {
            return Promise.resolve(attempt.result.session);
        }
        if (attempt.result?.state === "failed") {
            return Promise.reject(attempt.result.error);
        }
        if (!this.isCurrent(attempt)) {
            return Promise.reject(new Error("miniapp launch attempt is no longer active"));
        }

        return new Promise<MiniAppSession>((resolve, reject) => {
            attempt.waiters.add({ resolve, reject });
        });
    }

    resolve(attempt: LaunchAttempt, session: MiniAppSession) {
        if (
            !this.isCurrent(attempt) ||
            attempt.session !== session ||
            (attempt.cleanupSessions?.size ?? 0) > 0 ||
            attempt.phase === "cleaning" ||
            attempt.phase === "cleaning-mismatch" ||
            attempt.phase === "blocked"
        ) {
            return false;
        }

        this.clearTimer(attempt);
        attempt.result = { state: "ready", session };
        this.removeAttempt(attempt);
        for (const waiter of attempt.waiters) {
            waiter.resolve(session);
        }
        attempt.waiters.clear();
        return true;
    }

    reject(attempt: LaunchAttempt, error: unknown) {
        if (attempt.phase === "cleaning" && attempt.failurePromise) {
            return false;
        }
        return this.settleRejected(attempt, error);
    }

    private settleRejected(
        attempt: LaunchAttempt,
        error: unknown,
        releaseAttempt = true,
    ) {
        if (!this.isCurrent(attempt)) {
            return false;
        }

        const normalizedError = formatError(error);
        this.clearTimer(attempt);
        attempt.lastError = releaseAttempt
            ? normalizedError.message
            : (attempt.lastError ?? normalizedError.message);
        attempt.result = { state: "failed", error: normalizedError };
        if (releaseAttempt) {
            this.removeAttempt(attempt);
        } else {
            attempt.phase = "blocked";
            attempt.phaseStartedAt = Date.now();
        }
        for (const waiter of attempt.waiters) {
            waiter.reject(normalizedError);
        }
        attempt.waiters.clear();
        return true;
    }

    fail(
        attempt: LaunchAttempt,
        error: unknown,
        cleanup: () => Promise<boolean | void>,
        options?: { allowLateReadyRecovery?: boolean },
    ) {
        if (attempt.failurePromise) {
            return attempt.failurePromise;
        }
        if (!this.isCurrent(attempt)) {
            return Promise.resolve();
        }

        const normalizedError = formatError(error);
        this.clearTimer(attempt);
        attempt.phase = "cleaning";
        attempt.phaseStartedAt = Date.now();
        attempt.lastError = normalizedError.message;
        attempt.failurePromise = (async () => {
            let cleanupSucceeded = true;
            try {
                cleanupSucceeded = (await cleanup()) !== false;
            } catch (cleanupError) {
                cleanupSucceeded = false;
                const cleanupMessage = formatError(cleanupError).message;
                attempt.lastError = `${normalizedError.message}; cleanup failed: ${cleanupMessage}`;
            } finally {
                const remainingCleanupSessions =
                    attempt.cleanupSessions?.size ?? 0;
                if (remainingCleanupSessions > 0) {
                    cleanupSucceeded = false;
                    attempt.lastError =
                        `${attempt.lastError ?? normalizedError.message}; ` +
                        `${remainingCleanupSessions} miniapp session(s) still require cleanup`;
                }
                const lateSession = attempt.lateResolvedSession;
                if (
                    options?.allowLateReadyRecovery &&
                    !attempt.cancelRequested &&
                    !cleanupSucceeded &&
                    lateSession?.state === "ready" &&
                    isReusableSession(lateSession) &&
                    (attempt.cleanupSessions?.size ?? 0) === 0 &&
                    (!attempt.session || attempt.session === lateSession)
                ) {
                    attempt.failurePromise = undefined;
                    attempt.phase = "bootstrapping";
                    attempt.phaseStartedAt = Date.now();
                    this.bindSession(attempt, lateSession);
                    if (this.resolve(attempt, lateSession)) {
                        return;
                    }
                }
                this.settleRejected(
                    attempt,
                    normalizedError,
                    cleanupSucceeded,
                );
            }
        })();
        return attempt.failurePromise;
    }

    clearBlocked(attempt: LaunchAttempt) {
        if (
            this.attempts.get(attempt.appid) !== attempt ||
            this.activeAttempt !== attempt ||
            attempt.phase !== "blocked" ||
            attempt.session !== undefined ||
            attempt.lateResolvedSession !== undefined ||
            (attempt.cleanupSessions?.size ?? 0) > 0
        ) {
            return false;
        }
        this.removeAttempt(attempt);
        return true;
    }

    private clearTimer(attempt: LaunchAttempt) {
        if (attempt.timeout) {
            this.scheduler.clearTimeout(attempt.timeout);
            attempt.timeout = undefined;
        }
    }

    private removeAttempt(attempt: LaunchAttempt) {
        if (this.attempts.get(attempt.appid) === attempt) {
            this.attempts.delete(attempt.appid);
        }
        if (this.activeAttempt === attempt) {
            this.activeAttempt = undefined;
        }
    }
}
