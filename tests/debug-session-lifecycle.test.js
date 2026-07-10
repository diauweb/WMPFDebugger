import { describe, expect, test } from "bun:test";

import { DebugSessionLifecycle } from "../src/debug-session-lifecycle";
import { MiniAppLaunchCoordinator } from "../src/launch-coordinator";
import { createSession } from "../src/session";
import { MiniAppSessionRegistry } from "../src/session-registry";

const logger = {
    info() {},
    error() {},
    main_debug() {},
    frida_debug() {},
};

describe("DebugSessionLifecycle", () => {
    test("detach clears timers, pending work, and registry ownership", async () => {
        const launches = new MiniAppLaunchCoordinator();
        const registry = new MiniAppSessionRegistry(launches);
        const lifecycle = new DebugSessionLifecycle(logger, registry);
        const session = createSession();
        registry.add(session);

        let rejectPending;
        const pendingRejected = new Promise((resolve) => {
            rejectPending = resolve;
        });
        session.pendingCommands.set(1, {
            resolve() {},
            reject: rejectPending,
            timeout: setTimeout(() => {}, 60_000),
        });
        let closeResolved = false;
        session.closeWaiters.add({
            resolve: () => {
                closeResolved = true;
            },
            timeout: setTimeout(() => {}, 60_000),
        });
        session.foregroundKeepAlive = setInterval(() => {}, 60_000);

        lifecycle.detach(session, "test detach");

        expect((await pendingRejected).message).toBe("test detach");
        expect(closeResolved).toBe(true);
        expect(session.pendingCommands.size).toBe(0);
        expect(session.closeWaiters.size).toBe(0);
        expect(session.foregroundKeepAlive).toBeUndefined();
        expect(session.state).toBe("closing");
        expect(registry.values()).toEqual([]);
    });
});
