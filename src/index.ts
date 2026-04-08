import { parse_cli_options } from "./cli";
import { create_logger } from "./logger";
import { MiniAppSession, PendingSpawn } from "./session";
import { debug_server } from "./debug-server";
import { proxy_server } from "./proxy-server";
import { start_frida_server } from "./frida-server";

const main = async () => {
    const options = parse_cli_options();
    const logger = create_logger(options);
    const sessions = new Map<string, MiniAppSession>();
    const pendingSpawns = new Map<string, PendingSpawn>();
    const debugServer = debug_server(options, logger, sessions, pendingSpawns);
    proxy_server(options, logger, sessions, pendingSpawns, debugServer);
    start_frida_server(logger);
};

void main().catch((error) => {
    console.error(error);
    process.exit(1);
});
