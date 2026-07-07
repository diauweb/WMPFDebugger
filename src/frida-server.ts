import { promises } from "node:fs";
import path from "node:path";
import * as frida from "frida";

import { Logger } from "./logger";

type ResolvedWeChatTarget = {
    pid: number;
    version: number;
};

type FridaAttachment = {
    id: number;
    pid: number;
    version: number;
    session: frida.Session;
    script: frida.Script;
};

type FridaRuntimeState = {
    phase: "waiting" | "attaching" | "hooked" | "error";
    pid?: number;
    version?: number;
    attachedAt?: number;
    lastHookEventAt?: number;
    lastHookMessage?: string;
    hookInstalled: boolean;
    lastError?: string;
};

type FridaHookStatus = {
    active: boolean;
    phase: FridaRuntimeState["phase"];
    pid: number | null;
    version: number | null;
    hookInstalled: boolean;
    attachedAt: string | null;
    lastHookEventAt: string | null;
    lastHookMessage: string | null;
    lastError: string | null;
};

type MiniAppWindowHandle = {
    handle: number;
    createdAt: number;
};

type MiniAppWindowClaimOptions = {
    createdAfter?: number;
    graceMs?: number;
    fallbackToLatest?: boolean;
};

type FridaServerHandle = {
    getStatus: () => FridaHookStatus;
    claimMiniAppWindow: (
        options?: MiniAppWindowClaimOptions,
    ) => MiniAppWindowHandle | undefined;
};

type RecordedMiniAppWindow = MiniAppWindowHandle & {
    claimed: boolean;
};

const FRIDA_RETRY_INTERVAL_MS = 2_000;
const FRIDA_HEALTHCHECK_INTERVAL_MS = 3_000;
const FRIDA_READY_MESSAGE = "[hook] interceptors installed";

const toIsoString = (value?: number) =>
    value !== undefined ? new Date(value).toISOString() : null;

const formatError = (error: unknown) =>
    error instanceof Error ? error.message : String(error);

const formatFridaMessageError = (message: frida.ErrorMessage) =>
    message.stack ?? message.description;

const parseWindowHandle = (value: unknown) => {
    if (typeof value === "number" && Number.isFinite(value)) {
        return value;
    }
    if (typeof value !== "string") {
        return undefined;
    }

    const radix = value.startsWith("0x") ? 16 : 10;
    const parsed = Number.parseInt(
        radix === 16 ? value.slice(2) : value,
        radix,
    );
    return Number.isFinite(parsed) ? parsed : undefined;
};

const isWindowCreatedPayload = (
    payload: unknown,
): payload is { source: string; event: string; hwnd: unknown } =>
    typeof payload === "object" &&
    payload !== null &&
    (payload as any).source === "win32-window-recorder" &&
    (payload as any).event === "created";

const resetAttachmentState = (runtime: FridaRuntimeState) => {
    runtime.pid = undefined;
    runtime.version = undefined;
    runtime.attachedAt = undefined;
    runtime.lastHookEventAt = undefined;
    runtime.lastHookMessage = undefined;
    runtime.hookInstalled = false;
};

const getProjectRoot = () => {
    const entryFile = require.main?.filename ?? process.argv[1] ?? __filename;
    return entryFile
        ? path.join(path.dirname(entryFile), "..")
        : path.resolve(__dirname, "..");
};

const resolveWeChatTarget = async (
    localDevice: frida.Device,
): Promise<ResolvedWeChatTarget | null> => {
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
        return null;
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

    return {
        pid: wmpfPid,
        version: wmpfVersion,
    };
};

const loadHookScript = async (projectRoot: string) => {
    let scriptContent: string;
    let foregroundHookContent: string;
    try {
        scriptContent = await promises.readFile(
            path.join(projectRoot, "frida/hook.js"),
            "utf8",
        );
    } catch (error) {
        throw new Error("[frida] hook script not found");
    }

    try {
        foregroundHookContent = await promises.readFile(
            path.join(projectRoot, "frida/win32-foreground-hook.js"),
            "utf8",
        );
    } catch (error) {
        throw new Error("[frida] win32 foreground hook script not found");
    }

    return `${foregroundHookContent}\n${scriptContent}`;
};

const loadVersionConfig = async (projectRoot: string, wmpfVersion: number) => {
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

    return configContent;
};

const attachFrida = async (
    localDevice: frida.Device,
    projectRoot: string,
    target: ResolvedWeChatTarget,
    logger: Logger,
    runtime: FridaRuntimeState,
    attachmentId: number,
    isCurrentAttachment: (id: number) => boolean,
    requestReconnect: () => void,
    recordMiniAppWindow: (handle: number) => void,
) => {
    const session = await localDevice.attach(target.pid);
    try {
        const scriptContent = await loadHookScript(projectRoot);
        const configContent = await loadVersionConfig(projectRoot, target.version);
        const script = await session.createScript(
            scriptContent.replace("@@CONFIG@@", configContent),
        );

        script.message.connect((message: frida.Message) => {
            if (!isCurrentAttachment(attachmentId)) {
                return;
            }

            if (message.type === "error") {
                runtime.lastError = formatFridaMessageError(message);
                logger.error("[frida client]", message);
                requestReconnect();
                return;
            }

            if (typeof message.payload === "string") {
                runtime.lastHookEventAt = Date.now();
                runtime.lastHookMessage = message.payload;
                if (message.payload === FRIDA_READY_MESSAGE) {
                    runtime.hookInstalled = true;
                }
            } else if (isWindowCreatedPayload(message.payload)) {
                const handle = parseWindowHandle(message.payload.hwnd);
                if (handle !== undefined) {
                    runtime.lastHookEventAt = Date.now();
                    runtime.lastHookMessage = `window created: 0x${handle.toString(16)}`;
                    recordMiniAppWindow(handle);
                }
            }
            logger.frida_debug("[frida client]", message.payload);
        });
        script.destroyed.connect(() => {
            if (!isCurrentAttachment(attachmentId)) {
                return;
            }

            runtime.hookInstalled = false;
            runtime.lastError = "[frida] hook script destroyed";
            logger.info("[frida] hook script destroyed; scheduling rehook");
            requestReconnect();
        });
        session.detached.connect((reason, crash) => {
            if (!isCurrentAttachment(attachmentId)) {
                return;
            }

            runtime.hookInstalled = false;
            runtime.lastError = crash
                ? `[frida] session detached (${String(reason)}): ${crash.summary}`
                : `[frida] session detached (${String(reason)})`;
            logger.info(runtime.lastError);
            requestReconnect();
        });
        await script.load();

        runtime.phase = "hooked";
        runtime.pid = target.pid;
        runtime.version = target.version;
        runtime.attachedAt = Date.now();
        runtime.lastError = undefined;
        logger.info(
            `[frida] script loaded, WMPF version: ${target.version}, pid: ${target.pid}`,
        );
        logger.info(`[frida] you can now open any miniapps`);

        return {
            id: attachmentId,
            pid: target.pid,
            version: target.version,
            session,
            script,
        } satisfies FridaAttachment;
    } catch (error) {
        await cleanupSession(session);
        throw error;
    }
};

const sleep = (ms: number) =>
    new Promise<void>((resolve) => setTimeout(resolve, ms));

const buildStatusSnapshot = (
    runtime: FridaRuntimeState,
    attachment?: FridaAttachment,
): FridaHookStatus => ({
    active:
        attachment !== undefined &&
        !attachment.session.isDetached() &&
        !attachment.script.isDestroyed,
    phase: runtime.phase,
    pid: runtime.pid ?? null,
    version: runtime.version ?? null,
    hookInstalled: runtime.hookInstalled,
    attachedAt: toIsoString(runtime.attachedAt),
    lastHookEventAt: toIsoString(runtime.lastHookEventAt),
    lastHookMessage: runtime.lastHookMessage ?? null,
    lastError: runtime.lastError ?? null,
});

const cleanupSession = async (session?: frida.Session) => {
    if (!session || session.isDetached()) {
        return;
    }

    try {
        await session.detach();
    } catch (error) {
        // Ignore cleanup failures; the watchdog will reconcile state on the next pass.
    }
};

const cleanupAttachment = async (attachment?: FridaAttachment) =>
    cleanupSession(attachment?.session);

export const start_frida_server = (logger: Logger): FridaServerHandle => {
    const runtime: FridaRuntimeState = {
        phase: "waiting",
        hookInstalled: false,
    };
    const recordedMiniAppWindows: RecordedMiniAppWindow[] = [];
    let currentAttachment: FridaAttachment | undefined;
    let activeAttachmentId = 0;

    const recordMiniAppWindow = (handle: number) => {
        const existingWindow = recordedMiniAppWindows.find(
            (candidate) => !candidate.claimed && candidate.handle === handle,
        );
        if (existingWindow) {
            existingWindow.createdAt = Date.now();
            return;
        }

        recordedMiniAppWindows.push({
            handle,
            createdAt: Date.now(),
            claimed: false,
        });

        while (recordedMiniAppWindows.length > 50) {
            recordedMiniAppWindows.shift();
        }
        logger.info(`[frida] recorded miniapp hwnd: 0x${handle.toString(16)}`);
    };

    const claimMiniAppWindow = (options: MiniAppWindowClaimOptions = {}) => {
        const createdAfter =
            options.createdAfter === undefined
                ? undefined
                : options.createdAfter - (options.graceMs ?? 0);
        let recordedWindow =
            createdAfter === undefined
                ? undefined
                : recordedMiniAppWindows.find(
                      (candidate) =>
                          !candidate.claimed &&
                          candidate.createdAt >= createdAfter,
                  );

        if (!recordedWindow && options.fallbackToLatest) {
            recordedWindow = recordedMiniAppWindows
                .slice()
                .reverse()
                .find((candidate) => !candidate.claimed);
        }

        if (!recordedWindow) {
            return undefined;
        }

        recordedWindow.claimed = true;
        return {
            handle: recordedWindow.handle,
            createdAt: recordedWindow.createdAt,
        };
    };

    void (async () => {
        const projectRoot = getProjectRoot();
        let localDevice: frida.Device | undefined;
        let attachmentCounter = 0;
        let needsReconnect = false;
        let lastWaitingReason: string | undefined;

        const isCurrentAttachment = (attachmentId: number) =>
            activeAttachmentId === attachmentId;
        const requestReconnect = () => {
            needsReconnect = true;
        };

        while (true) {
            try {
                localDevice ??= await frida.getLocalDevice();
                const target = await resolveWeChatTarget(localDevice);

                if (
                    currentAttachment &&
                    (needsReconnect ||
                        currentAttachment.session.isDetached() ||
                        currentAttachment.script.isDestroyed ||
                        !target ||
                        currentAttachment.pid !== target.pid ||
                        currentAttachment.version !== target.version)
                ) {
                    await cleanupAttachment(currentAttachment);
                    currentAttachment = undefined;
                    activeAttachmentId = 0;
                    needsReconnect = false;
                    resetAttachmentState(runtime);
                    runtime.phase = target ? "attaching" : "waiting";
                    runtime.pid = target?.pid;
                    runtime.version = target?.version;
                }

                if (!target) {
                    runtime.phase = "waiting";
                    resetAttachmentState(runtime);
                    if (lastWaitingReason !== "missing-process") {
                        logger.info("[frida] waiting for WeChat process...");
                        lastWaitingReason = "missing-process";
                    }
                    await sleep(FRIDA_RETRY_INTERVAL_MS);
                    continue;
                }

                lastWaitingReason = undefined;

                if (!currentAttachment) {
                    attachmentCounter += 1;
                    activeAttachmentId = attachmentCounter;
                    runtime.phase = "attaching";
                    runtime.pid = target.pid;
                    runtime.version = target.version;
                    runtime.hookInstalled = false;
                    currentAttachment = await attachFrida(
                        localDevice,
                        projectRoot,
                        target,
                        logger,
                        runtime,
                        attachmentCounter,
                        isCurrentAttachment,
                        requestReconnect,
                        recordMiniAppWindow,
                    );
                }

                await sleep(FRIDA_HEALTHCHECK_INTERVAL_MS);
            } catch (error) {
                await cleanupAttachment(currentAttachment);
                currentAttachment = undefined;
                activeAttachmentId = 0;
                localDevice = undefined;
                needsReconnect = false;
                runtime.phase = "error";
                resetAttachmentState(runtime);
                runtime.lastError = formatError(error);
                logger.error("[frida] watchdog error:", error);
                await sleep(FRIDA_RETRY_INTERVAL_MS);
            }
        }
    })();

    return {
        getStatus: () => buildStatusSnapshot(runtime, currentAttachment),
        claimMiniAppWindow,
    };
};

export { FridaHookStatus, FridaServerHandle, MiniAppWindowHandle };
