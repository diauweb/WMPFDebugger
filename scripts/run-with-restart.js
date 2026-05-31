#!/usr/bin/env node

const { spawn } = require("node:child_process");
const path = require("node:path");

const projectRoot = path.resolve(__dirname, "..");
const entryPoint = path.join(projectRoot, "src/index.ts");
const childArgs = process.argv.slice(2);
const childCommand = process.env.WMPF_CHILD_COMMAND ?? "bun";
const childProcessArgs = ["run", entryPoint, ...childArgs];

const restartDelayMs = Number(process.env.WMPF_RESTART_DELAY_MS ?? 1000);
const maxRestarts = Number(process.env.WMPF_MAX_RESTARTS ?? 0);

let child = null;
let childExited = true;
let restartCount = 0;
let stopping = false;

const timestamp = () => new Date().toISOString();

const log = (...messages) => {
    console.error(`[supervisor] ${timestamp()}`, ...messages);
};

const stopChild = (signal) => {
    stopping = true;
    if (!child || childExited) {
        return;
    }

    log(`forwarding ${signal} to child pid ${child.pid}`);
    child.kill(signal);
    setTimeout(() => {
        if (child && !childExited) {
            log(`child did not stop after ${signal}; killing`);
            child.kill("SIGKILL");
        }
    }, 5000).unref();
};

const startChild = () => {
    log(`starting child: ${childCommand} ${childProcessArgs.join(" ")}`);
    childExited = false;
    child = spawn(childCommand, childProcessArgs, {
        cwd: projectRoot,
        env: process.env,
        shell: process.platform === "win32",
        stdio: "inherit",
    });

    child.on("error", (error) => {
        childExited = true;
        log("failed to spawn child:", error.stack ?? error.message);
        process.exit(1);
    });

    child.on("exit", (code, signal) => {
        childExited = true;
        const cleanExit = code === 0 || stopping;
        log(
            `child exited with code ${code ?? "null"} signal ${signal ?? "null"}`,
        );

        if (cleanExit) {
            process.exit(code ?? 0);
            return;
        }

        restartCount += 1;
        if (maxRestarts > 0 && restartCount > maxRestarts) {
            log(`restart limit reached (${maxRestarts}); exiting`);
            process.exit(code ?? 1);
            return;
        }

        log(`restarting child in ${restartDelayMs}ms (attempt ${restartCount})`);
        setTimeout(startChild, restartDelayMs);
    });
};

process.on("SIGINT", () => stopChild("SIGINT"));
process.on("SIGTERM", () => stopChild("SIGTERM"));

startChild();
