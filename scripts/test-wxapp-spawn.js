#!/usr/bin/env bun

const DEFAULT_WAIT_MS = 3000;

const printUsage = () => {
    console.log(`Usage:
  bun scripts/test-wxapp-spawn.js status
  bun scripts/test-wxapp-spawn.js spawn <appid>
  bun scripts/test-wxapp-spawn.js full-test <appid> [--wait-ms <ms>]
`);
};

const parseArgs = (argv) => {
    const args = argv.slice(2);
    if (args.length === 0 || args.includes("-h") || args.includes("--help")) {
        return { command: "help", waitMs: DEFAULT_WAIT_MS, positional: [] };
    }

    const command = args[0];
    const positional = [];
    let waitMs = DEFAULT_WAIT_MS;

    for (let i = 1; i < args.length; i += 1) {
        const value = args[i];
        if (value === "--wait-ms") {
            i += 1;
            waitMs = Number(args[i] || waitMs);
            continue;
        }
        positional.push(value);
    }

    return { command, waitMs, positional };
};

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const printResult = (label, value) => {
    console.log(`== ${label} ==`);
    console.log(JSON.stringify(value, null, 2));
};

const printError = (error) => {
    const payload = {
        name: error instanceof Error ? error.name : "Error",
        message:
            error instanceof Error ? error.message : String(error ?? "unknown error"),
    };
    if (error instanceof Error && error.stack) {
        payload.stack = error.stack;
    }
    printResult("error", payload);
};

const ensureBun = () => {
    if (typeof Bun === "undefined") {
        throw new Error("This script must be run with Bun.");
    }
};

const loadBridge = async () => import("../src/wechat-host.ts");

const runStatus = async () => {
    const { get_wechat_status } = await loadBridge();
    const status = await get_wechat_status();
    printResult("wechat status", {
        platform: process.platform,
        arch: process.arch,
        ...status,
    });
};

const runSpawn = async (appid) => {
    const { spawn_miniapp } = await loadBridge();
    const result = await spawn_miniapp(appid);
    printResult("spawn request", {
        platform: process.platform,
        arch: process.arch,
        appid,
        ...result,
    });
    console.log(
        "The bridge only confirms that the launch request was sent. Verify the miniapp in the WeChat UI.",
    );
};

const runFullTest = async (appid, waitMs) => {
    const { get_wechat_status, spawn_miniapp } = await loadBridge();

    const before = await get_wechat_status();
    printResult("wechat status before", {
        platform: process.platform,
        arch: process.arch,
        ...before,
    });

    const spawn = await spawn_miniapp(appid);
    printResult("spawn request", {
        platform: process.platform,
        arch: process.arch,
        appid,
        ...spawn,
    });

    console.log(`waiting ${waitMs}ms before re-checking window status...`);
    await sleep(waitMs);

    const after = await get_wechat_status();
    printResult("wechat status after", {
        platform: process.platform,
        arch: process.arch,
        ...after,
    });

    console.log(
        "If the miniapp still does not open, the failure is inside the Windows host bridge or WeChat message handling rather than the HTTP API.",
    );
};

const main = async () => {
    ensureBun();

    const { command, waitMs, positional } = parseArgs(process.argv);

    if (command === "help") {
        printUsage();
        return;
    }

    if (command === "status") {
        await runStatus();
        return;
    }

    if (command === "spawn") {
        const appid = positional[0];
        if (!appid) {
            printUsage();
            process.exitCode = 1;
            return;
        }
        await runSpawn(appid);
        return;
    }

    if (command === "full-test") {
        const appid = positional[0];
        if (!appid) {
            printUsage();
            process.exitCode = 1;
            return;
        }
        await runFullTest(appid, waitMs);
        return;
    }

    printUsage();
    process.exitCode = 1;
};

void main().catch((error) => {
    printError(error);
    process.exitCode = 1;
});
