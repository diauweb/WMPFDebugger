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
    const { start_frida_server } = require("./frida-server") as typeof import("./frida-server");
    const sessions = new Map<string, MiniAppSession>();
    const pendingSpawns = new Map<string, PendingSpawn>();
    const debugServer = debug_server(options, logger, sessions, pendingSpawns);
    const fridaServer = start_frida_server(logger);
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
