import { afterEach, describe, expect, test } from "bun:test";

import {
    LaunchBlockedError,
    LaunchBusyError,
    MiniAppLaunchCoordinator,
} from "../src/launch-coordinator";

const coordinators = [];

const createCoordinator = (scheduler) => {
    const coordinator = new MiniAppLaunchCoordinator(scheduler);
    coordinators.push(coordinator);
    return coordinator;
};

const createManualScheduler = () => {
    const scheduled = [];
    return {
        scheduled,
        scheduler: {
            setTimeout(callback) {
                const timer = {
                    unref() {
                        return timer;
                    },
                };
                scheduled.push({ callback, timer, cleared: false });
                return timer;
            },
            clearTimeout(timer) {
                const entry = scheduled.find(
                    (candidate) => candidate.timer === timer,
                );
                if (entry) {
                    entry.cleared = true;
                }
            },
        },
    };
};

const createSession = () => ({
    id: "session",
    title: "miniapp",
    state: "bootstrapping",
    attached: false,
    createdAt: Date.now(),
    updatedAt: Date.now(),
    debugSocket: { readyState: 1 },
    messageCounter: 0,
    internalCommandCounter: 1_000_000_000,
    pendingCommands: new Map(),
    pendingContexts: new Map(),
    closeWaiters: new Set(),
});

afterEach(() => {
    for (const coordinator of coordinators.splice(0)) {
        const attempt = coordinator.getActive();
        if (attempt) {
            coordinator.reject(attempt, new Error("test cleanup"));
        }
    }
});

describe("MiniAppLaunchCoordinator", () => {
    test("joins callers for the same app and resolves every waiter", async () => {
        const coordinator = createCoordinator();
        const first = coordinator.createOrJoin("wx-one");
        const second = coordinator.createOrJoin("wx-one");
        expect(first.created).toBe(true);
        expect(second.created).toBe(false);
        expect(second.attempt).toBe(first.attempt);

        coordinator.setPhase(first.attempt, "dispatching");
        coordinator.setPhase(first.attempt, "waiting-for-connection");
        const session = createSession();
        expect(coordinator.claimActiveSession(session)).toBe(first.attempt);
        coordinator.setPhase(first.attempt, "bootstrapping");

        const waiters = [
            coordinator.waitForReady(first.attempt),
            coordinator.waitForReady(second.attempt),
            coordinator.waitForReady(first.attempt),
        ];
        expect(coordinator.resolve(first.attempt, session)).toBe(true);
        expect(await Promise.all(waiters)).toEqual([session, session, session]);
        expect(coordinator.getActive()).toBeUndefined();
    });

    test("serializes different app launches", () => {
        const coordinator = createCoordinator();
        coordinator.createOrJoin("wx-one");
        expect(() => coordinator.createOrJoin("wx-two")).toThrow(LaunchBusyError);
    });

    test("does not claim an unrelated connection before dispatch", () => {
        const coordinator = createCoordinator();
        coordinator.createOrJoin("wx-one");
        expect(coordinator.claimActiveSession(createSession())).toBeUndefined();
    });

    test("a connection during dispatch cannot have its bootstrap phase overwritten", () => {
        const coordinator = createCoordinator();
        const attempt = coordinator.createOrJoin("wx-one").attempt;
        coordinator.setPhase(attempt, "dispatching");
        coordinator.claimActiveSession(createSession());
        expect(coordinator.setPhase(attempt, "bootstrapping")).toBe(true);

        expect(
            coordinator.setPhase(attempt, "waiting-for-connection"),
        ).toBe(false);
        expect(attempt.phase).toBe("bootstrapping");
    });

    test("an old timer cannot reject a replacement attempt", async () => {
        const { scheduler, scheduled } = createManualScheduler();
        const coordinator = createCoordinator(scheduler);
        const first = coordinator.createOrJoin("wx-one").attempt;
        coordinator.setPhase(first, "dispatching");
        coordinator.setPhase(first, "waiting-for-connection", 60_000, (attempt) => {
            coordinator.reject(attempt, new Error("old timeout"));
        });
        const oldTimeoutCallback = scheduled[0].callback;
        coordinator.reject(first, new Error("first failed"));

        const second = coordinator.createOrJoin("wx-one").attempt;
        coordinator.setPhase(second, "dispatching");
        coordinator.setPhase(second, "waiting-for-connection", 60_000, (attempt) => {
            coordinator.reject(attempt, new Error("second timeout"));
        });
        oldTimeoutCallback();
        expect(coordinator.get("wx-one")).toBe(second);

        const waiting = coordinator.waitForReady(second);
        scheduled[1].callback();
        await expect(waiting).rejects.toThrow("second timeout");
    });

    test("a queued timeout cannot reject a session that already became ready", () => {
        const { scheduler, scheduled } = createManualScheduler();
        const coordinator = createCoordinator(scheduler);
        const attempt = coordinator.createOrJoin("wx-one").attempt;
        coordinator.setPhase(attempt, "dispatching");
        const session = createSession();
        coordinator.claimActiveSession(session);
        let timeoutCount = 0;
        coordinator.setPhase(attempt, "bootstrapping", 60_000, () => {
            timeoutCount += 1;
        });
        const timeoutCallback = scheduled[0].callback;

        expect(coordinator.resolve(attempt, session)).toBe(true);
        timeoutCallback();
        expect(timeoutCount).toBe(0);
    });

    test("late work from an old session cannot settle a new attempt", async () => {
        const coordinator = createCoordinator();
        const first = coordinator.createOrJoin("wx-one").attempt;
        coordinator.setPhase(first, "dispatching");
        const oldSession = createSession();
        coordinator.claimActiveSession(oldSession);
        coordinator.reject(first, new Error("expired"));

        const second = coordinator.createOrJoin("wx-one").attempt;
        coordinator.setPhase(second, "dispatching");
        const newSession = createSession();
        coordinator.claimActiveSession(newSession);
        const waiting = coordinator.waitForReady(second);

        expect(coordinator.resolve(first, oldSession)).toBe(false);
        expect(coordinator.reject(first, new Error("late failure"))).toBe(false);
        expect(coordinator.resolve(second, newSession)).toBe(true);
        expect(await waiting).toBe(newSession);
    });

    test("a mismatched provisional connection can be replaced after identity validation", () => {
        const coordinator = createCoordinator();
        const attempt = coordinator.createOrJoin("wx-one").attempt;
        coordinator.setPhase(attempt, "dispatching");
        const wrongSession = createSession();
        coordinator.claimActiveSession(wrongSession);
        coordinator.setPhase(attempt, "bootstrapping");

        expect(
            coordinator.releaseMismatchedSession(attempt, wrongSession),
        ).toBe(true);
        expect(wrongSession.launchAttemptId).toBeUndefined();
        expect(wrongSession.requestedAppId).toBeUndefined();
        expect(attempt.phase).toBe("cleaning-mismatch");
        expect(
            coordinator.completeMismatchedSessionCleanup(
                attempt,
                wrongSession,
            ),
        ).toBe("waiting");

        const matchingSession = createSession();
        const adopted = coordinator.adoptResolvedSession(
            matchingSession,
            "wx-one",
        );
        expect(adopted?.attempt).toBe(attempt);
        expect(coordinator.resolve(attempt, matchingSession)).toBe(true);
    });

    test("cancelling mismatch cleanup releases after the wrong owner closes", async () => {
        const coordinator = createCoordinator();
        const attempt = coordinator.createOrJoin("wx-one").attempt;
        coordinator.setPhase(attempt, "dispatching");
        const wrongSession = createSession();
        coordinator.claimActiveSession(wrongSession);
        coordinator.setPhase(attempt, "bootstrapping");
        coordinator.releaseMismatchedSession(attempt, wrongSession);
        const waiting = coordinator.waitForReady(attempt);

        coordinator.requestCancellation(attempt);
        expect(
            coordinator.completeMismatchedSessionCleanup(
                attempt,
                wrongSession,
            ),
        ).toBeUndefined();

        await expect(waiting).rejects.toThrow("cancelled");
        expect(coordinator.getActive()).toBeUndefined();
    });

    test("cancelling mismatch cleanup blocks when a late owner remains", async () => {
        const coordinator = createCoordinator();
        const attempt = coordinator.createOrJoin("wx-one").attempt;
        coordinator.setPhase(attempt, "dispatching");
        const wrongSession = createSession();
        coordinator.claimActiveSession(wrongSession);
        coordinator.setPhase(attempt, "bootstrapping");
        coordinator.releaseMismatchedSession(attempt, wrongSession);
        const lateSession = createSession();
        lateSession.state = "ready";
        coordinator.adoptResolvedSession(lateSession, "wx-one");
        const waiting = coordinator.waitForReady(attempt);

        coordinator.requestCancellation(attempt);
        coordinator.completeMismatchedSessionCleanup(
            attempt,
            wrongSession,
        );

        await expect(waiting).rejects.toThrow("cancelled");
        expect(attempt.phase).toBe("blocked");
        expect(coordinator.isCleanupSession(lateSession)).toBe(true);
        expect(coordinator.clearBlocked(attempt)).toBe(false);
    });

    test("a blocked mismatched runtime cannot be bypassed by a late match", async () => {
        const coordinator = createCoordinator();
        const attempt = coordinator.createOrJoin("wx-one").attempt;
        coordinator.setPhase(attempt, "dispatching");
        const wrongSession = createSession();
        coordinator.claimActiveSession(wrongSession);
        coordinator.setPhase(attempt, "bootstrapping");
        coordinator.releaseMismatchedSession(attempt, wrongSession);

        await coordinator.fail(
            attempt,
            new Error("mismatched runtime remained open"),
            async () => false,
        );
        expect(attempt.phase).toBe("blocked");

        const matchingSession = createSession();
        matchingSession.state = "ready";
        expect(
            coordinator.adoptResolvedSession(matchingSession, "wx-one"),
        ).toBeUndefined();
        expect(attempt.phase).toBe("blocked");

        const lateReadySession = createSession();
        lateReadySession.state = "ready";
        expect(
            coordinator.recordLateResolvedSession(
                lateReadySession,
                "wx-one",
            ),
        ).toBe(false);
        expect(coordinator.isCleanupSession(lateReadySession)).toBe(true);
        expect(coordinator.isSessionQuarantined(lateReadySession)).toBe(true);
        expect(coordinator.getOwningAttempt(lateReadySession)).toBe(attempt);
    });

    test("failure cleanup is single-flight and rejects after cleanup", async () => {
        const coordinator = createCoordinator();
        const attempt = coordinator.createOrJoin("wx-one").attempt;
        const waiting = coordinator.waitForReady(attempt);
        let cleanupCount = 0;
        let finishCleanup;
        const cleanupGate = new Promise((resolve) => {
            finishCleanup = resolve;
        });
        const cleanup = async () => {
            cleanupCount += 1;
            await cleanupGate;
        };

        const firstFailure = coordinator.fail(attempt, new Error("timeout"), cleanup);
        const secondFailure = coordinator.fail(attempt, new Error("ignored"), cleanup);
        expect(firstFailure).toBe(secondFailure);
        expect(cleanupCount).toBe(1);
        expect(coordinator.getActive()).toBe(attempt);
        expect(
            coordinator.reject(attempt, new Error("miniapp disconnected")),
        ).toBe(false);

        finishCleanup();
        await firstFailure;
        await expect(waiting).rejects.toThrow("timeout");
        expect(coordinator.getActive()).toBeUndefined();
    });

    test("a cleaning attempt cannot resolve as ready", async () => {
        const coordinator = createCoordinator();
        const attempt = coordinator.createOrJoin("wx-one").attempt;
        const session = createSession();
        coordinator.bindSession(attempt, session);
        let finishCleanup;
        const cleanupGate = new Promise((resolve) => {
            finishCleanup = resolve;
        });
        const failing = coordinator.fail(
            attempt,
            new Error("timeout"),
            async () => cleanupGate,
        );

        expect(coordinator.resolve(attempt, session)).toBe(false);
        finishCleanup(true);
        await failing;
    });

    test("failed cleanup blocks a new generation until explicitly cleared", async () => {
        const coordinator = createCoordinator();
        const attempt = coordinator.createOrJoin("wx-one").attempt;
        const waiting = coordinator.waitForReady(attempt);

        await coordinator.fail(attempt, new Error("connection timeout"), async () => false);
        await expect(waiting).rejects.toThrow("connection timeout");
        expect(attempt.phase).toBe("blocked");
        expect(() => coordinator.createOrJoin("wx-one")).toThrow(
            LaunchBlockedError,
        );

        expect(coordinator.clearBlocked(attempt)).toBe(true);
        expect(coordinator.createOrJoin("wx-one").created).toBe(true);
    });

    test("tracked cleanup obligations prevent a successful callback from releasing", async () => {
        const coordinator = createCoordinator();
        const attempt = coordinator.createOrJoin("wx-one").attempt;
        const oldSession = createSession();
        const waiting = coordinator.waitForReady(attempt);
        coordinator.addCleanupSession(attempt, oldSession);

        await coordinator.fail(
            attempt,
            new Error("bootstrap failed"),
            async () => true,
        );

        await expect(waiting).rejects.toThrow("bootstrap failed");
        expect(attempt.phase).toBe("blocked");
        expect(attempt.lastError).toContain("still require cleanup");
        expect(() => coordinator.createOrJoin("wx-one")).toThrow(
            LaunchBlockedError,
        );
    });

    test("a matching late session reconciles a blocked launch", async () => {
        const coordinator = createCoordinator();
        const attempt = coordinator.createOrJoin("wx-one").attempt;
        await coordinator.fail(attempt, new Error("connection timeout"), async () => false);
        expect(attempt.phase).toBe("blocked");

        const session = createSession();
        const adopted = coordinator.adoptResolvedSession(session, "wx-one");
        expect(adopted?.attempt).toBe(attempt);
        expect(coordinator.resolve(attempt, session)).toBe(true);
        expect(coordinator.getActive()).toBeUndefined();
    });

    test("a late ready session safely clears a blocked launch without an old owner", async () => {
        const coordinator = createCoordinator();
        const attempt = coordinator.createOrJoin("wx-one").attempt;
        await coordinator.fail(
            attempt,
            new Error("connection timeout"),
            async () => false,
        );
        expect(attempt.phase).toBe("blocked");

        const session = createSession();
        session.state = "ready";
        expect(coordinator.recordLateResolvedSession(session, "wx-one")).toBe(
            true,
        );
        expect(attempt.result).toEqual({ state: "ready", session });
        expect(coordinator.getActive()).toBeUndefined();
    });

    test("cancellation quarantines late sessions and prevents premature clearing", async () => {
        const coordinator = createCoordinator();
        const attempt = coordinator.createOrJoin("wx-one").attempt;
        await coordinator.fail(
            attempt,
            new Error("connection timeout"),
            async () => false,
        );
        coordinator.requestCancellation(attempt);

        const session = createSession();
        session.state = "ready";
        expect(
            coordinator.adoptResolvedSession(session, "wx-one"),
        ).toBeUndefined();
        expect(coordinator.isCleanupSession(session)).toBe(true);
        expect(coordinator.clearBlocked(attempt)).toBe(false);

        coordinator.completeCleanupSession(attempt, session);
        expect(coordinator.clearBlocked(attempt)).toBe(true);
    });

    test("cancellation during cleanup prevents late-ready recovery", async () => {
        const coordinator = createCoordinator();
        const attempt = coordinator.createOrJoin("wx-one").attempt;
        const waiting = coordinator.waitForReady(attempt);
        let finishCleanup;
        const cleanupGate = new Promise((resolve) => {
            finishCleanup = resolve;
        });
        const failing = coordinator.fail(
            attempt,
            new Error("connection timeout"),
            async () => cleanupGate,
            { allowLateReadyRecovery: true },
        );
        const session = createSession();
        session.state = "ready";
        coordinator.adoptResolvedSession(session, "wx-one");

        coordinator.requestCancellation(attempt);
        finishCleanup(false);
        await failing;

        await expect(waiting).rejects.toThrow("connection timeout");
        expect(attempt.phase).toBe("blocked");
        expect(coordinator.isCleanupSession(session)).toBe(true);
    });

    test("cancellation immediately quarantines an unidentified late connection", async () => {
        const coordinator = createCoordinator();
        const attempt = coordinator.createOrJoin("wx-one").attempt;
        coordinator.setPhase(attempt, "dispatching");
        attempt.windowHandle = 707;
        attempt.windowClosureObserved = true;
        coordinator.requestCancellation(attempt);
        const session = createSession();

        expect(coordinator.trackCancelledSession(session)).toBe(attempt);
        expect(coordinator.isCleanupSession(session)).toBe(true);
        expect(coordinator.getOwningAttempt(session)).toBe(attempt);
        expect(session.launchStartedAt).toBe(attempt.dispatchStartedAt);
        expect(session.windowHandle).toBe(707);
        expect(session.windowClosureObserved).toBe(true);
        expect(session.requestedAppId).toBeUndefined();
    });

    test("a ready matching session can win while failed cleanup is settling", async () => {
        const coordinator = createCoordinator();
        const attempt = coordinator.createOrJoin("wx-one").attempt;
        const waiting = coordinator.waitForReady(attempt);
        let finishCleanup;
        const cleanupGate = new Promise((resolve) => {
            finishCleanup = resolve;
        });
        const failing = coordinator.fail(
            attempt,
            new Error("connection timeout"),
            async () => cleanupGate,
            { allowLateReadyRecovery: true },
        );

        const session = createSession();
        session.state = "ready";
        expect(
            coordinator.adoptResolvedSession(session, "wx-one"),
        ).toBeUndefined();
        finishCleanup(false);
        await failing;

        expect(await waiting).toBe(session);
        expect(coordinator.getActive()).toBeUndefined();
    });

    test("a transient late connection cannot replace a ready recovery candidate", async () => {
        const coordinator = createCoordinator();
        const attempt = coordinator.createOrJoin("wx-one").attempt;
        const waiting = coordinator.waitForReady(attempt);
        let finishCleanup;
        const cleanupGate = new Promise((resolve) => {
            finishCleanup = resolve;
        });
        const failing = coordinator.fail(
            attempt,
            new Error("connection timeout"),
            async () => cleanupGate,
            { allowLateReadyRecovery: true },
        );

        const readySession = createSession();
        readySession.state = "ready";
        coordinator.adoptResolvedSession(readySession, "wx-one");
        const transientSession = createSession();
        transientSession.state = "closing";
        transientSession.debugSocket.readyState = 3;
        coordinator.adoptResolvedSession(transientSession, "wx-one");

        finishCleanup(false);
        await failing;
        expect(await waiting).toBe(readySession);
        expect(coordinator.getActive()).toBeUndefined();
    });

    test("a late candidate that becomes ready replaces a stuck bootstrap candidate", async () => {
        const coordinator = createCoordinator();
        const attempt = coordinator.createOrJoin("wx-one").attempt;
        const waiting = coordinator.waitForReady(attempt);
        let finishCleanup;
        const cleanupGate = new Promise((resolve) => {
            finishCleanup = resolve;
        });
        const failing = coordinator.fail(
            attempt,
            new Error("connection timeout"),
            async () => cleanupGate,
            { allowLateReadyRecovery: true },
        );

        const stuckSession = createSession();
        coordinator.adoptResolvedSession(stuckSession, "wx-one");
        const recoveredSession = createSession();
        coordinator.adoptResolvedSession(recoveredSession, "wx-one");
        recoveredSession.state = "ready";
        coordinator.recordLateResolvedSession(recoveredSession, "wx-one");

        finishCleanup(false);
        await failing;
        expect(await waiting).toBe(recoveredSession);
        expect(coordinator.getActive()).toBeUndefined();
    });
});
