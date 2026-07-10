import { CliOptions } from "./cli";
import { FridaServerHandle } from "./frida-server";
import {
    LaunchAttempt,
    LaunchBlockedError,
    LaunchBusyError,
    MiniAppLaunchError,
    MiniAppLaunchCoordinator,
} from "./launch-coordinator";
import { Logger } from "./logger";
import {
    FRIDA_HOOK_READY_TIMEOUT_MS,
    MINIAPP_BOOTSTRAP_TIMEOUT_MS,
    MINIAPP_CONNECTION_TIMEOUT_MS,
    MiniAppSession,
} from "./session";
import { MiniAppSessionRegistry } from "./session-registry";
import { spawn_miniapp, WeChatStatus } from "./wechat-host";

type CloseResult = { closed: boolean; forced: boolean };

type DebugLifecycle = {
    cleanupLaunchAttempt: (
        attempt: LaunchAttempt,
        reason: string,
    ) => Promise<CloseResult>;
    killMiniApp: (
        session: MiniAppSession,
        reason: string,
    ) => Promise<CloseResult>;
};

type SpawnMiniApp = (appid: string) => Promise<WeChatStatus>;

type SingletonState = "ready" | "bootstrapping" | "clear";

export class MiniAppLaunchService {
    constructor(
        private readonly options: CliOptions,
        private readonly logger: Logger,
        private readonly sessions: MiniAppSessionRegistry,
        private readonly launches: MiniAppLaunchCoordinator,
        private readonly debugLifecycle: DebugLifecycle,
        private readonly frida: FridaServerHandle,
        private readonly spawn: SpawnMiniApp = spawn_miniapp,
    ) {}

    startOrJoin(appid: string) {
        const result = this.launches.createOrJoin(appid);
        if (result.created) {
            result.attempt.redispatch = () =>
                this.dispatch(result.attempt);
            result.attempt.launchPromise = this.run(result.attempt);
            result.attempt.launchPromise.catch(() => undefined);
        }
        return result.attempt;
    }

    async waitForDispatch(attempt: LaunchAttempt) {
        await attempt.launchPromise;
        if (attempt.failurePromise) {
            await attempt.failurePromise;
        }
        if (attempt.result?.state === "failed") {
            throw attempt.result.error;
        }
    }

    async waitForReady(attempt: LaunchAttempt) {
        const readySession = this.sessions.getReady(attempt.appid);
        if (readySession) {
            if (this.launches.isCurrent(attempt)) {
                this.launches.bindSession(attempt, readySession);
                this.launches.resolve(attempt, readySession);
            }
            return readySession;
        }
        return this.launches.waitForReady(attempt);
    }

    getStatusCode(error: unknown) {
        if (
            error instanceof LaunchBusyError ||
            error instanceof LaunchBlockedError
        ) {
            return 409;
        }
        if (error instanceof MiniAppLaunchError) {
            return error.statusCode;
        }
        return 502;
    }

    private async run(attempt: LaunchAttempt) {
        try {
            const existingState = await this.inspectSingleton(attempt, false);
            if (existingState !== "clear" || !this.launches.isCurrent(attempt)) {
                return;
            }

            await this.waitForHook(attempt);
            if (!this.launches.isCurrent(attempt)) {
                return;
            }

            for (let pass = 0; pass < 2; pass += 1) {
                const singletonState = await this.inspectSingleton(attempt, true);
                if (
                    singletonState !== "clear" ||
                    !this.launches.isCurrent(attempt)
                ) {
                    return;
                }
            }

            await this.dispatch(attempt);
        } catch (error) {
            const launchError =
                error instanceof Error
                    ? error
                    : new MiniAppLaunchError("failed to launch miniapp", 500);
            if (this.launches.isCurrent(attempt)) {
                await this.fail(attempt, launchError);
            }
            if (attempt.result?.state === "ready") {
                return;
            }
            throw launchError;
        }
    }

    private async waitForHook(attempt: LaunchAttempt) {
        if (this.options.noFrida) {
            return;
        }

        this.launches.setPhase(attempt, "waiting-for-hook");
        let hookStatus;
        try {
            hookStatus = await this.frida.waitUntilReady(
                FRIDA_HOOK_READY_TIMEOUT_MS,
            );
        } catch (error) {
            throw new MiniAppLaunchError(
                error instanceof Error
                    ? error.message
                    : "Frida hook is not ready",
                503,
            );
        }
        if (this.launches.isCurrent(attempt)) {
            this.logger.info(
                `[api] launch ${attempt.id} hook ready: pid=${hookStatus.pid}, version=${hookStatus.version}`,
            );
        }
    }

    private async inspectSingleton(
        attempt: LaunchAttempt,
        closeExisting: boolean,
    ): Promise<SingletonState> {
        const readySession = this.sessions.getReady(attempt.appid);
        if (readySession) {
            this.launches.bindSession(attempt, readySession);
            this.launches.resolve(attempt, readySession);
            return "ready";
        }

        const matchingSession = this.sessions.find(attempt.appid);
        if (
            matchingSession?.state === "bootstrapping" &&
            this.sessions.isSocketOpen(matchingSession)
        ) {
            this.armBootstrapTimeout(attempt, matchingSession);
            return "bootstrapping";
        }

        if (!closeExisting) {
            return "clear";
        }

        for (const session of this.sessions.values()) {
            const closeResult = await this.debugLifecycle.killMiniApp(
                session,
                `closing existing singleton before launch ${attempt.id}`,
            );
            if (!closeResult.closed && !closeResult.forced) {
                throw new MiniAppLaunchError(
                    `existing miniapp ${session.id} could not be closed`,
                    409,
                );
            }
        }
        return "clear";
    }

    private armBootstrapTimeout(
        attempt: LaunchAttempt,
        session: MiniAppSession,
    ) {
        this.launches.bindSession(attempt, session);
        this.launches.setPhase(
            attempt,
            "bootstrapping",
            MINIAPP_BOOTSTRAP_TIMEOUT_MS,
            (expiredAttempt) => {
                void this.fail(
                    expiredAttempt,
                    new MiniAppLaunchError(
                        `miniapp bootstrap timed out for ${expiredAttempt.appid} (launch ${expiredAttempt.id})`,
                        504,
                    ),
                );
            },
        );
    }

    private async dispatch(attempt: LaunchAttempt) {
        if (!this.launches.setPhase(attempt, "dispatching")) {
            return;
        }
        attempt.dispatchCount = (attempt.dispatchCount ?? 0) + 1;

        let status;
        try {
            status = await this.spawn(attempt.appid);
        } catch (error) {
            throw new MiniAppLaunchError(
                error instanceof Error
                    ? error.message
                    : "failed to dispatch miniapp launch",
                502,
            );
        }
        if (
            !this.launches.isCurrent(attempt) ||
            attempt.phase !== "dispatching"
        ) {
            return;
        }

        this.launches.setPhase(
            attempt,
            "waiting-for-connection",
            MINIAPP_CONNECTION_TIMEOUT_MS,
            (expiredAttempt) => {
                void this.fail(
                    expiredAttempt,
                    new MiniAppLaunchError(
                        `miniapp did not connect to the debugger (launch ${expiredAttempt.id})`,
                        504,
                    ),
                );
            },
        );
        this.logger.info(
            `[api] spawn requested: ${attempt.appid} via ${status.window} (launch ${attempt.id})`,
        );
    }

    private fail(attempt: LaunchAttempt, error: Error) {
        this.logger.error(
            `[api] launch ${attempt.id} failed in ${attempt.phase} (${attempt.appid}):`,
            error,
        );
        return this.launches.fail(
            attempt,
            error,
            async () => this.cleanup(attempt, error.message),
            { allowLateReadyRecovery: true },
        );
    }

    private async cleanup(attempt: LaunchAttempt, reason: string) {
        const closeResult = await this.debugLifecycle.cleanupLaunchAttempt(
            attempt,
            reason,
        );
        if (!attempt.session && attempt.dispatchStartedAt === undefined) {
            return true;
        }
        return closeResult.closed || closeResult.forced;
    }
}
