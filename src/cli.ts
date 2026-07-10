import { parseArgs } from "node:util";

type CliOptions = {
    debugPort: number;
    cdpPort: number;
    sqlcipherDbRoot?: string;
    debugMain: boolean;
    debugFrida: boolean;
    noFrida: boolean;
};

// default debugging port, do not change
const DEBUG_PORT = 9421;
// CDP port, change to whatever you like
// use this port by navigating to devtools://devtools/bundled/inspector.html?ws=127.0.0.1:${CDP_PORT}
const CDP_PORT = 62000;

const print_help = () => {
    console.log(`Usage: bun run src/index.ts [options]

Options:
  --debug-port <port>  Remote debug server port (fixed at ${DEBUG_PORT})
  --cdp-port <port>    CDP proxy server port (default: ${CDP_PORT})
  --sqlcipher-db-root <path>
                       Root folder for SQLCipher .db files
  --debug-main         Output main process debug messages
  --debug-frida        Output Frida client messages
  --no-frida           Start HTTP/CDP server without the Frida watchdog
  -h, --help           Show this help message`);
};

const parse_port = (
    name: string,
    value: string | undefined,
    defaultValue: number,
) => {
    if (value === undefined) {
        return defaultValue;
    }

    const port = Number(value);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
        throw new Error(`[main] invalid ${name}: ${value}`);
    }

    return port;
};

const parse_cli_options = (): CliOptions => {
    const { values } = parseArgs({
        options: {
            "debug-port": { type: "string" },
            "cdp-port": { type: "string" },
            "sqlcipher-db-root": { type: "string" },
            "debug-main": { type: "boolean" },
            "debug-frida": { type: "boolean" },
            "no-frida": { type: "boolean" },
            help: { type: "boolean", short: "h" },
        },
        allowPositionals: false,
    });

    if (values.help) {
        print_help();
        process.exit(0);
    }

    const debugPort = parse_port(
        "--debug-port",
        values["debug-port"],
        DEBUG_PORT,
    );
    if (debugPort !== DEBUG_PORT) {
        throw new Error(
            `[main] --debug-port must remain ${DEBUG_PORT}; the WMPF runtime endpoint is fixed`,
        );
    }

    return {
        debugPort,
        cdpPort: parse_port("--cdp-port", values["cdp-port"], CDP_PORT),
        sqlcipherDbRoot: values["sqlcipher-db-root"],
        debugMain: values["debug-main"] ?? false,
        debugFrida: values["debug-frida"] ?? false,
        noFrida: values["no-frida"] ?? false,
    };
};

export { CliOptions, parse_cli_options };
