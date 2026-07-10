import { describe, expect, test } from "bun:test";

import { MiniAppLaunchCoordinator } from "../src/launch-coordinator";
import { MiniAppLaunchService } from "../src/miniapp-launch-service";
import { MiniAppSessionRegistry } from "../src/session-registry";

const logger = {
    info() {},
    error() {},
    main_debug() {},
    frida_debug() {},
};

const options = {
    debugPort: 9421,
    cdpPort: 62000,
    debugMain: false,
    debugFrida: false,
    noFrida: false,
};

const debugLifecycle = {
    async cleanupLaunchAttempt() {
        return { closed: true, forced: false };
    },
    async killMiniApp() {
        return { closed: true, forced: false };
    },
};

describe("MiniAppLaunchService", () => {
    test("waits for hook readiness before native dispatch", async () => {
        const launches = new MiniAppLaunchCoordinator();
        const sessions = new MiniAppSessionRegistry(launches);
        let releaseHook;
        const hookReady = new Promise((resolve) => {
            releaseHook = resolve;
        });
        const frida = {
            getStatus() {},
            claimMiniAppWindow() {},
            waitUntilReady: () => hookReady,
        };
        const dispatched = [];
        const service = new MiniAppLaunchService(
            options,
            logger,
            sessions,
            launches,
            debugLifecycle,
            frida,
            async (appid) => {
                dispatched.push(appid);
                return { window: "main" };
            },
        );

        const attempt = service.startOrJoin("wx-one");
        await Promise.resolve();
        expect(dispatched).toEqual([]);
        releaseHook({
            active: true,
            phase: "hooked",
            pid: 1,
            version: 1,
            hookInstalled: true,
            attachedAt: null,
            lastHookEventAt: null,
            lastHookMessage: null,
            lastError: null,
        });
        await service.waitForDispatch(attempt);

        expect(dispatched).toEqual(["wx-one"]);
        expect(attempt.phase).toBe("waiting-for-connection");
        launches.reject(attempt, new Error("test cleanup"));
    });
});
