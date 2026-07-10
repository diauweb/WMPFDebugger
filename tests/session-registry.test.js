import { describe, expect, test } from "bun:test";

import { MiniAppLaunchCoordinator } from "../src/launch-coordinator";
import { createSession } from "../src/session";
import { MiniAppSessionRegistry } from "../src/session-registry";

const makeReady = (session, appid) => {
    session.resolvedAppId = appid;
    session.state = "ready";
    session.debugSocket = { readyState: 1 };
    session.appService = {
        targetId: "target",
        sessionId: "cdp-session",
        frameId: "frame",
        contextId: 1,
    };
    return session;
};

describe("MiniAppSessionRegistry", () => {
    test("prefers a ready session over a newer closing alias", () => {
        const launches = new MiniAppLaunchCoordinator();
        const registry = new MiniAppSessionRegistry(launches);
        const ready = makeReady(createSession(), "wx-one");
        const closing = createSession("wx-one");
        closing.state = "closing";
        closing.debugSocket = { readyState: 1 };
        closing.updatedAt = ready.updatedAt + 1_000;
        registry.add(ready);
        registry.add(closing);

        expect(registry.find("wx-one")).toBe(ready);
        expect(registry.getReady("wx-one")).toBe(ready);
    });

    test("quarantined sessions are not exposed as debuggable", () => {
        const launches = new MiniAppLaunchCoordinator();
        const registry = new MiniAppSessionRegistry(launches);
        const session = makeReady(createSession(), "wx-one");
        registry.add(session);
        const attempt = launches.createOrJoin("wx-one").attempt;
        launches.addCleanupSession(attempt, session);

        expect(registry.getReady("wx-one")).toBeUndefined();
        expect(registry.listDebuggable()).toEqual([]);
        expect(registry.serializeAll({
            debugPort: 9421,
            cdpPort: 62000,
            debugMain: false,
            debugFrida: false,
            noFrida: false,
        })[0]).toMatchObject({
            quarantined: true,
            targetUrl: null,
        });

        launches.completeCleanupSession(attempt, session);
        launches.reject(attempt, new Error("test cleanup"));
    });

    test("rekey and remove update every alias owned by a session", () => {
        const launches = new MiniAppLaunchCoordinator();
        const registry = new MiniAppSessionRegistry(launches);
        const session = createSession();
        registry.add(session);
        registry.rekey(session, "wx-one");

        expect(registry.getExact("wx-one")).toBe(session);
        expect(registry.values()).toEqual([session]);
        registry.remove(session);
        expect(registry.values()).toEqual([]);
    });
});
