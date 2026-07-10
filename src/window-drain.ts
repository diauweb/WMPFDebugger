export type WindowDrainOptions = {
    initialHandle?: number;
    claim: () => number | undefined;
    isLive: (handle: number) => boolean;
    close: (handle: number) => Promise<boolean>;
    onPendingHandle?: (handle: number | undefined) => void;
    previouslyObserved?: boolean;
    quietMs: number;
    timeoutMs: number;
    pollMs: number;
    now?: () => number;
    sleep?: (ms: number) => Promise<void>;
};

export type WindowDrainResult = {
    closed: boolean;
    observed: boolean;
    timedOut: boolean;
    pendingHandle?: number;
};

const defaultSleep = (ms: number) =>
    new Promise<void>((resolve) => setTimeout(resolve, ms));

export const drainCorrelatedWindows = async (
    options: WindowDrainOptions,
): Promise<WindowDrainResult> => {
    const now = options.now ?? Date.now;
    const sleep = options.sleep ?? defaultSleep;
    const drainDeadline = now() + options.timeoutMs;
    let quietDeadline = now() + options.quietMs;
    let pendingHandle = options.initialHandle;
    let observed = options.previouslyObserved ?? false;

    while (now() < quietDeadline && now() < drainDeadline) {
        if (pendingHandle !== undefined) {
            options.onPendingHandle?.(pendingHandle);
            if (
                options.isLive(pendingHandle) &&
                !(await options.close(pendingHandle))
            ) {
                return {
                    closed: false,
                    observed,
                    timedOut: false,
                    pendingHandle,
                };
            }

            observed = true;
            pendingHandle = undefined;
            options.onPendingHandle?.(undefined);
            quietDeadline = now() + options.quietMs;
            const yieldMs = Math.min(
                options.pollMs,
                quietDeadline - now(),
                drainDeadline - now(),
            );
            if (yieldMs > 0) {
                await sleep(yieldMs);
            }
            continue;
        }

        pendingHandle = options.claim();
        if (pendingHandle !== undefined) {
            options.onPendingHandle?.(pendingHandle);
            continue;
        }

        const waitMs = Math.min(
            options.pollMs,
            quietDeadline - now(),
            drainDeadline - now(),
        );
        if (waitMs > 0) {
            await sleep(waitMs);
        }
    }

    const quietElapsed = now() >= quietDeadline;
    return {
        closed: observed && quietElapsed && pendingHandle === undefined,
        observed,
        timedOut: !quietElapsed && now() >= drainDeadline,
        pendingHandle,
    };
};
