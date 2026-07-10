import { parse_cli_options } from "./cli";
import { MiniAppLaunchCoordinator } from "./launch-coordinator";
import { create_logger } from "./logger";
import { MiniAppSessionRegistry } from "./session-registry";
import { install_process_guards } from "./process-guards";

const main = async () => {
    const options = parse_cli_options();
    const logger = create_logger(options);
    install_process_guards(logger);
    const { debug_server } = require("./debug-server") as typeof import("./debug-server");
    const { proxy_server } = require("./proxy-server") as typeof import("./proxy-server");
    const launches = new MiniAppLaunchCoordinator();
    const sessionRegistry = new MiniAppSessionRegistry(launches);
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
            waitUntilReady: async () => ({
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
        }
        : (() => {
            const { start_frida_server } = require("./frida-server") as typeof import("./frida-server");
            return start_frida_server(logger);
        })();
    const debugServer = debug_server(
        options,
        logger,
        sessionRegistry,
        launches,
        fridaServer,
    );
    proxy_server(
        options,
        logger,
        sessionRegistry,
        launches,
        debugServer,
        fridaServer,
    );
};

void main().catch((error) => {
    console.error(error);
    process.exit(1);
});
