import { Logger } from "./logger";

let fatalExitStarted = false;

const stringifyReason = (reason: unknown) =>
    reason instanceof Error ? reason.stack ?? reason.message : String(reason);

const exitAfterFatalLog = () => {
    process.exitCode = 1;
    setTimeout(() => {
        process.exit(1);
    }, 100).unref();
};

const logFatal = (logger: Logger, source: string, reason: unknown) => {
    logger.error(`[fatal] ${source}:`, stringifyReason(reason));
};

const startFatalExit = (logger: Logger, source: string, reason: unknown) => {
    if (fatalExitStarted) {
        return;
    }

    fatalExitStarted = true;
    logFatal(logger, source, reason);
    exitAfterFatalLog();
};

const signalExitCode = (signal: NodeJS.Signals) => {
    switch (signal) {
        case "SIGINT":
            return 130;
        case "SIGTERM":
            return 143;
        default:
            return 1;
    }
};

export const report_fatal_error = (
    logger: Logger,
    source: string,
    reason: unknown,
) => {
    startFatalExit(logger, source, reason);
};

export const install_process_guards = (logger: Logger) => {
    process.on("uncaughtException", (error) => {
        startFatalExit(logger, "uncaught exception", error);
    });

    process.on("unhandledRejection", (reason) => {
        startFatalExit(logger, "unhandled promise rejection", reason);
    });

    process.on("warning", (warning) => {
        logger.error("[process warning]", warning.stack ?? warning.message);
    });

    const handleSignal = (signal: NodeJS.Signals) => {
        if (fatalExitStarted) {
            return;
        }

        fatalExitStarted = true;
        logger.info(`[shutdown] received ${signal}`);
        process.exitCode = signalExitCode(signal);
        setTimeout(() => {
            process.exit(process.exitCode ?? 1);
        }, 100).unref();
    };

    process.on("SIGINT", handleSignal);
    process.on("SIGTERM", handleSignal);

    process.on("exit", (code) => {
        logger.info(`[process] exiting with code ${code}`);
    });
};
