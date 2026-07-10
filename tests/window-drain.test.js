import { describe, expect, test } from "bun:test";

import { drainCorrelatedWindows } from "../src/window-drain";

const createClock = () => {
    let now = 0;
    return {
        now: () => now,
        advance: (ms) => {
            now += ms;
        },
        sleep: async (ms) => {
            now += ms;
        },
    };
};

describe("drainCorrelatedWindows", () => {
    test("closes every correlated handle before the quiet interval", async () => {
        const clock = createClock();
        const handles = [101, 202];
        const closed = [];
        const result = await drainCorrelatedWindows({
            claim: () => handles.shift(),
            isLive: () => true,
            close: async (handle) => {
                closed.push(handle);
                return true;
            },
            quietMs: 20,
            timeoutMs: 100,
            pollMs: 5,
            ...clock,
        });

        expect(closed).toEqual([101, 202]);
        expect(result.closed).toBe(true);
        expect(result.timedOut).toBe(false);
    });

    test("does not report success when handles continue through the hard deadline", async () => {
        const clock = createClock();
        let nextHandle = 0;
        const result = await drainCorrelatedWindows({
            claim: () => ++nextHandle,
            isLive: () => false,
            close: async () => true,
            quietMs: 20,
            timeoutMs: 100,
            pollMs: 5,
            ...clock,
        });

        expect(result.closed).toBe(false);
        expect(result.observed).toBe(true);
        expect(result.timedOut).toBe(true);
    });

    test("retains a handle whose close cannot be confirmed", async () => {
        const clock = createClock();
        let pendingHandle;
        const result = await drainCorrelatedWindows({
            initialHandle: 303,
            claim: () => undefined,
            isLive: () => true,
            close: async () => false,
            onPendingHandle: (handle) => {
                pendingHandle = handle;
            },
            quietMs: 20,
            timeoutMs: 100,
            pollMs: 5,
            ...clock,
        });

        expect(result.closed).toBe(false);
        expect(result.pendingHandle).toBe(303);
        expect(pendingHandle).toBe(303);
    });

    test("continues past a helper handle and stops fallback after the primary closes", async () => {
        const clock = createClock();
        const handles = [401, 402, 403];
        const closed = [];
        let socketOpen = true;
        const result = await drainCorrelatedWindows({
            claim: () => (socketOpen ? handles.shift() : undefined),
            isLive: () => true,
            close: async (handle) => {
                closed.push(handle);
                if (handle === 402) {
                    socketOpen = false;
                }
                return true;
            },
            quietMs: 20,
            timeoutMs: 100,
            pollMs: 5,
            ...clock,
        });

        expect(closed).toEqual([401, 402]);
        expect(result.closed).toBe(true);
    });

    test("a retry can confirm quiet after an earlier drain closed a window", async () => {
        const clock = createClock();
        const result = await drainCorrelatedWindows({
            previouslyObserved: true,
            claim: () => undefined,
            isLive: () => true,
            close: async () => true,
            quietMs: 20,
            timeoutMs: 100,
            pollMs: 5,
            ...clock,
        });

        expect(result.closed).toBe(true);
        expect(result.observed).toBe(true);
    });

    test("retains a handle claimed exactly at the quiet deadline", async () => {
        const clock = createClock();
        let claimed = false;
        let pendingHandle;
        const result = await drainCorrelatedWindows({
            previouslyObserved: true,
            claim: () => {
                if (claimed) {
                    return undefined;
                }
                claimed = true;
                clock.advance(20);
                return 909;
            },
            isLive: () => true,
            close: async () => true,
            onPendingHandle: (handle) => {
                pendingHandle = handle;
            },
            quietMs: 20,
            timeoutMs: 100,
            pollMs: 5,
            now: clock.now,
            sleep: clock.sleep,
        });

        expect(result.closed).toBe(false);
        expect(result.pendingHandle).toBe(909);
        expect(pendingHandle).toBe(909);
    });
});
