import { parse_cli_options } from "./cli";
import { create_logger } from "./logger";
import type { MiniAppSession, PendingSpawn } from "./session";
import { install_process_guards } from "./process-guards";

const main = async () => {
    const options = parse_cli_options();
    const logger = create_logger(options);
    install_process_guards(logger);
    const { debug_server } = require("./debug-server") as typeof import("./debug-server");
    const { proxy_server } = require("./proxy-server") as typeof import("./proxy-server");
    const sessions = new Map<string, MiniAppSession>();
    const pendingSpawns = new Map<string, PendingSpawn>();
    const fridaServer = options.noFrida
        ? {
            getStatus: () => ({
                active: false,
                phase: "waiting" as const,
                pid: null,
                version: null,
                hookInstalled: false,
                attachedAt: null,
                lastHookEventAt: null,
                lastHookMessage: null,
                lastError: "frida disabled",
            }),
            claimMiniAppWindow: () => undefined,
        }
        : (() => {
            const { start_frida_server } = require("./frida-server") as typeof import("./frida-server");
            return start_frida_server(logger);
        })();
    const debugServer = debug_server(
        options,
        logger,
        sessions,
        pendingSpawns,
        fridaServer,
    );
    proxy_server(
        options,
        logger,
        sessions,
        pendingSpawns,
        debugServer,
        fridaServer,
    );
};

void main().catch((error) => {
    console.error(error);
    process.exit(1);
});
