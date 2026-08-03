import { promises } from "node:fs";
import path from "node:path";
import * as frida from "frida";

import { Logger } from "./logger";

type ResolvedWeChatTarget = {
    pid: number;
    version: number;
    selection: {
        candidates: Array<{
            pid: number;
            childCount: number;
            childPids: number[];
        }>;
        selectedChildCount: number;
        selectedChildPids: number[];
        tieCount: number;
    };
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
    targetSelection?: {
        resolvedAt: number;
        selectedPid: number;
        candidates: Array<{
            pid: number;
            childCount: number;
            childPids: number[];
        }>;
        selectedChildCount: number;
        selectedChildPids: number[];
        tieCount: number;
    };
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
    targetSelection: {
        resolvedAt: string;
        selectedPid: number;
        candidates: Array<{
            pid: number;
            childCount: number;
            childPids: number[];
        }>;
        selectedChildCount: number;
        selectedChildPids: number[];
        tieCount: number;
    } | null;
};

type MiniAppWindowHandle = {
    handle: number;
    sequence: number;
    createdAt: number;
    evidence: "created" | "shown" | "snapshot";
    pid: number;
    tid: number;
    className: string;
    title: string;
    visible: boolean;
    destroyedAt?: number;
};

type MiniAppWindowQuery = {
    afterSequence?: number;
    createdAfter?: number;
    createdBefore?: number;
    pid?: number;
};

type FridaServerHandle = {
    getStatus: () => FridaHookStatus;
    waitUntilReady: (timeoutMs: number) => Promise<FridaHookStatus>;
    getMiniAppWindowCursor: () => number;
    listMiniAppWindowCandidates: (
        query?: MiniAppWindowQuery,
    ) => MiniAppWindowHandle[];
};

type HookEventPayload = {
    source: "wmpf-hook";
    event: string;
    hwnd?: unknown;
    pid?: unknown;
    tid?: unknown;
    at?: unknown;
    className?: unknown;
    title?: unknown;
    visible?: unknown;
    visibleBefore?: unknown;
    visibleAfter?: unknown;
    scene?: unknown;
    message?: unknown;
    windows?: Array<{
        hwnd?: unknown;
        tid?: unknown;
        className?: unknown;
        title?: unknown;
        visible?: unknown;
    }>;
};

const FRIDA_RETRY_INTERVAL_MS = 2_000;
const FRIDA_HEALTHCHECK_INTERVAL_MS = 3_000;
const FRIDA_READY_POLL_INTERVAL_MS = 100;
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

const parsePositiveInteger = (value: unknown) =>
    typeof value === "number" && Number.isSafeInteger(value) && value > 0
        ? value
        : undefined;

const parseOptionalString = (value: unknown) =>
    typeof value === "string" ? value : undefined;

const isHookEventPayload = (payload: unknown): payload is HookEventPayload =>
    typeof payload === "object" &&
    payload !== null &&
    (payload as any).source === "wmpf-hook" &&
    typeof (payload as any).event === "string";

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
    const childPidsByParent = new Map<number, number[]>();
    for (const processInfo of processes) {
        if (processInfo.name !== "WeChatAppEx.exe") {
            continue;
        }

        const parentPid = processInfo.parameters.ppid;
        if (typeof parentPid !== "number" || parentPid <= 0) {
            continue;
        }

        const childPids = childPidsByParent.get(parentPid) ?? [];
        childPids.push(processInfo.pid);
        childPidsByParent.set(parentPid, childPids);
    }

    let wmpfPid: number | undefined;
    let wmpfPidCount = 0;
    for (const [parentPid, childPids] of childPidsByParent.entries()) {
        const count = childPids.length;
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
        selection: {
            candidates: Array.from(childPidsByParent.entries())
                .map(([pid, childPids]) => ({
                    pid,
                    childCount: childPids.length,
                    childPids: [...childPids].sort((left, right) => left - right),
                }))
                .sort((left, right) => left.pid - right.pid),
            selectedChildCount: wmpfPidCount,
            selectedChildPids: [
                ...(childPidsByParent.get(wmpfPid) ?? []),
            ].sort((left, right) => left - right),
            tieCount: Array.from(childPidsByParent.values()).filter(
                (childPids) => childPids.length === wmpfPidCount,
            ).length,
        },
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
    handleHookEvent: (event: HookEventPayload) => void,
) => {
    const resolvedAt = Date.now();
    runtime.targetSelection = {
        resolvedAt,
        selectedPid: target.pid,
        ...target.selection,
    };
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
                runtime.phase = "error";
                runtime.hookInstalled = false;
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
            } else if (isHookEventPayload(message.payload)) {
                runtime.lastHookEventAt = Date.now();
                runtime.lastHookMessage = `hook event: ${message.payload.event}`;
                handleHookEvent(message.payload);
            }
            logger.frida_debug("[frida client]", message.payload);
        });
        script.destroyed.connect(() => {
            if (!isCurrentAttachment(attachmentId)) {
                return;
            }

            runtime.hookInstalled = false;
            runtime.phase = "error";
            runtime.lastError = "[frida] hook script destroyed";
            logger.info("[frida] hook script destroyed; scheduling rehook");
            requestReconnect();
        });
        session.detached.connect((reason, crash) => {
            if (!isCurrentAttachment(attachmentId)) {
                return;
            }

            runtime.hookInstalled = false;
            runtime.phase = "error";
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
    targetSelection: runtime.targetSelection
        ? {
              ...runtime.targetSelection,
              resolvedAt: new Date(
                  runtime.targetSelection.resolvedAt,
              ).toISOString(),
              candidates: runtime.targetSelection.candidates.map(
                  (candidate) => ({
                      ...candidate,
                      childPids: [...candidate.childPids],
                  }),
              ),
              selectedChildPids: [
                  ...runtime.targetSelection.selectedChildPids,
              ],
          }
        : null,
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
    const recordedMiniAppWindows = new Map<string, MiniAppWindowHandle>();
    let currentAttachment: FridaAttachment | undefined;
    let activeAttachmentId = 0;
    let miniAppWindowSequence = 0;

    const upsertWindow = (
        event: HookEventPayload,
        evidence: MiniAppWindowHandle["evidence"],
        handle: number,
        at: number,
    ) => {
        const pid = parsePositiveInteger(event.pid) ?? 0;
        const tid = parsePositiveInteger(event.tid) ?? 0;
        const className = parseOptionalString(event.className) ?? "";
        const title = parseOptionalString(event.title) ?? "";
        const visible =
            event.visible === true || event.visibleAfter === true;
        const key = `${pid}:${handle}`;
        const existing = recordedMiniAppWindows.get(key);
        if (existing && existing.destroyedAt === undefined) {
            existing.sequence = Math.max(existing.sequence, miniAppWindowSequence + 1);
            miniAppWindowSequence = Math.max(
                miniAppWindowSequence,
                existing.sequence,
            );
            existing.createdAt = Math.min(existing.createdAt, at);
            if (evidence === "created" || existing.evidence === "snapshot") {
                existing.evidence = evidence;
            }
            existing.pid = pid || existing.pid;
            existing.tid = tid || existing.tid;
            existing.className = className || existing.className;
            existing.title = title || existing.title;
            existing.visible = visible || existing.visible;
            return existing;
        }

        const entry: MiniAppWindowHandle = {
            handle,
            sequence: ++miniAppWindowSequence,
            createdAt: at,
            evidence,
            pid,
            tid,
            className,
            title,
            visible,
        };
        recordedMiniAppWindows.set(key, entry);
        return entry;
    };

    const handleHookEvent = (event: HookEventPayload) => {
        const at = typeof event.at === "number" ? event.at : Date.now();
        const handle = parseWindowHandle(event.hwnd);
        switch (event.event) {
            case "window-created":
                if (handle !== undefined) {
                    const entry = upsertWindow(
                        event,
                        "created",
                        handle,
                        at,
                    );
                    logger.info(
                        `[hook] window created 0x${handle.toString(16)} ` +
                            `(pid=${entry.pid}, class=${entry.className}, title=${entry.title})`,
                    );
                }
                break;
            case "window-shown":
                if (handle !== undefined) {
                    const entry = upsertWindow(event, "shown", handle, at);
                    logger.info(
                        `[hook] window shown 0x${handle.toString(16)} ` +
                            `(pid=${entry.pid}, visible=${entry.visible})`,
                    );
                }
                break;
            case "window-title-changed":
                if (handle !== undefined) {
                    const entry = upsertWindow(
                        event,
                        "created",
                        handle,
                        at,
                    );
                    logger.info(
                        `[hook] window title 0x${handle.toString(16)} ` +
                            `-> "${entry.title}"`,
                    );
                }
                break;
            case "window-destroyed":
                if (handle !== undefined) {
                    const pid = parsePositiveInteger(event.pid) ?? 0;
                    const entry = recordedMiniAppWindows.get(
                        `${pid}:${handle}`,
                    );
                    if (entry) {
                        entry.destroyedAt = at;
                        entry.visible = false;
                        logger.info(
                            `[hook] window destroyed 0x${handle.toString(16)} (pid=${pid})`,
                        );
                    }
                }
                break;
            case "windows-snapshot":
                for (const window of event.windows ?? []) {
                    const snapshotHandle = parseWindowHandle(window.hwnd);
                    if (snapshotHandle !== undefined) {
                        upsertWindow(
                            {
                                ...event,
                                hwnd: window.hwnd,
                                tid: window.tid,
                                className: window.className,
                                title: window.title,
                                visible: window.visible,
                            },
                            "snapshot",
                            snapshotHandle,
                            at,
                        );
                    }
                }
                logger.info(
                    `[hook] window snapshot: ${(event.windows ?? []).length} host windows`,
                );
                break;
            case "miniapp-load":
                logger.info(
                    `[hook] miniapp load scene=${event.scene ?? "?"}`,
                );
                break;
            case "hook-error":
                logger.error(`[hook] ${event.message ?? "unknown hook error"}`);
                break;
            case "recorder-installed":
                logger.info("[hook] window recorder installed");
                break;
        }
    };

    const listMiniAppWindowCandidates = (
        query: MiniAppWindowQuery = {},
    ) =>
        Array.from(recordedMiniAppWindows.values())
            .filter(
                (candidate) =>
                    candidate.destroyedAt === undefined &&
                    (query.afterSequence === undefined ||
                        candidate.sequence > query.afterSequence) &&
                    (query.createdAfter === undefined ||
                        candidate.createdAt >= query.createdAfter) &&
                    (query.createdBefore === undefined ||
                        candidate.createdAt <= query.createdBefore) &&
                    (query.pid === undefined || candidate.pid === query.pid),
            )
            .sort((left, right) => left.sequence - right.sequence)
            .map((candidate) => ({ ...candidate }));

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

                runtime.targetSelection = {
                    resolvedAt: Date.now(),
                    selectedPid: target.pid,
                    ...target.selection,
                };

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
                        handleHookEvent,
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
        getMiniAppWindowCursor: () => miniAppWindowSequence,
        waitUntilReady: async (timeoutMs: number) => {
            const deadline = Date.now() + timeoutMs;
            let status = buildStatusSnapshot(runtime, currentAttachment);
            while (
                status.phase !== "hooked" ||
                !status.active ||
                !status.hookInstalled
            ) {
                const remaining = deadline - Date.now();
                if (remaining <= 0) {
                    const detail = status.lastError ??
                        `phase=${status.phase}, active=${status.active}, hookInstalled=${status.hookInstalled}`;
                    throw new Error(`Frida hook is not ready: ${detail}`);
                }
                await sleep(Math.min(FRIDA_READY_POLL_INTERVAL_MS, remaining));
                status = buildStatusSnapshot(runtime, currentAttachment);
            }
            return status;
        },
        listMiniAppWindowCandidates,
    };
};

export { FridaHookStatus, FridaServerHandle, MiniAppWindowHandle };
