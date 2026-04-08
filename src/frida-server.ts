import { promises } from "node:fs";
import path from "node:path";
import * as frida from "frida";

import { Logger } from "./logger";

const frida_server = async (logger: Logger) => {
    const localDevice = await frida.getLocalDevice();
    const entryFile = require.main?.filename ?? process.argv[1] ?? __filename;
    const processes = await localDevice.enumerateProcesses({
        scope: frida.Scope.Metadata,
    });
    const parentPidCounts = new Map<number, number>();
    for (const processInfo of processes) {
        if (processInfo.name !== "WeChatAppEx.exe") {
            continue;
        }

        const parentPid = processInfo.parameters.ppid;
        if (typeof parentPid !== "number" || parentPid <= 0) {
            continue;
        }

        parentPidCounts.set(
            parentPid,
            (parentPidCounts.get(parentPid) ?? 0) + 1,
        );
    }

    let wmpfPid: number | undefined;
    let wmpfPidCount = 0;
    for (const [parentPid, count] of parentPidCounts.entries()) {
        if (count >= wmpfPidCount) {
            wmpfPid = parentPid;
            wmpfPidCount = count;
        }
    }
    if (wmpfPid === undefined) {
        throw new Error("[frida] WeChatAppEx.exe process not found");
    }
    const wmpfProcess = processes.find(
        (processInfo) => processInfo.pid === wmpfPid,
    );
    if (!wmpfProcess) {
        throw new Error(`[frida] process metadata not found for pid ${wmpfPid}`);
    }
    const wmpfProcessPath = wmpfProcess.parameters.path as string | undefined;
    const wmpfVersionMatch = wmpfProcessPath?.match(/\d+/g);
    const wmpfVersion = Number(
        wmpfVersionMatch && wmpfVersionMatch.length > 0
            ? wmpfVersionMatch[wmpfVersionMatch.length - 1]
            : undefined,
    );
    if (!Number.isInteger(wmpfVersion) || wmpfVersion <= 0) {
        throw new Error("[frida] error in find wmpf version");
    }

    const session = await localDevice.attach(Number(wmpfPid));

    const projectRoot = entryFile
        ? path.join(path.dirname(entryFile), "..")
        : path.resolve(__dirname, "..");
    let scriptContent: string;
    try {
        scriptContent = await promises.readFile(
            path.join(projectRoot, "frida/hook.js"),
            "utf8",
        );
    } catch (error) {
        throw new Error("[frida] hook script not found");
    }

    let configContent: string;
    try {
        const configPath = path.join(
            projectRoot,
            "frida/config",
            `addresses.${wmpfVersion}.json`,
        );
        configContent = JSON.stringify(
            JSON.parse(await promises.readFile(configPath, "utf8")),
        );
    } catch (error) {
        throw new Error(`[frida] version config not found: ${wmpfVersion}`);
    }

    const script = await session.createScript(
        scriptContent.replace("@@CONFIG@@", configContent),
    );
    script.message.connect((message: frida.Message) => {
        if (message.type === "error") {
            logger.error("[frida client]", message);
            return;
        }

        logger.frida_debug("[frida client]", message.payload);
    });
    await script.load();
    logger.info(
        `[frida] script loaded, WMPF version: ${wmpfVersion}, pid: ${wmpfPid}`,
    );
    logger.info(`[frida] you can now open any miniapps`);
};

const sleep = (ms: number) =>
    new Promise<void>((resolve) => setTimeout(resolve, ms));

export const start_frida_server = (logger: Logger) => {
    void (async () => {
        let attempt = 0;
        while (true) {
            try {
                await frida_server(logger);
                return;
            } catch (error) {
                attempt += 1;
                logger.error(
                    `[frida] initialization failed (attempt ${attempt}):`,
                    error,
                );
                await sleep(2_000);
            }
        }
    })();
};
