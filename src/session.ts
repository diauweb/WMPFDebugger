import { randomUUID } from "node:crypto";
import WebSocket, { RawData } from "ws";

import { CliOptions } from "./cli";

export type PendingCommand = {
    resolve: (payload: any) => void;
    reject: (error: Error) => void;
    timeout: NodeJS.Timeout;
};

export type PendingSpawnWaiter = {
    resolve: (session: MiniAppSession) => void;
    reject: (error: Error) => void;
};

export type PendingContext = {
    frameId?: string;
    resolve: (contextId: number) => void;
    reject: (error: Error) => void;
    timeout: NodeJS.Timeout;
};

export type CloseWaiter = {
    resolve: () => void;
    timeout: NodeJS.Timeout;
};

export type AppServiceBinding = {
    targetId: string;
    sessionId: string;
    frameId: string;
    contextId: number;
};

export type MiniAppWindowIdentity = {
    handle: number;
    pid: number;
    tid: number;
    className: string;
    owner: string | null;
    root: string | null;
    rootOwner: string | null;
    launchId: string;
    fridaObservedAt: number;
    processStartTime: string;
    appIdConfirmed: boolean;
    verifiedAt: number;
};

export type MiniAppSessionState = "bootstrapping" | "ready" | "closing";

export type PendingSpawn = {
    id: string;
    appid: string;
    createdAt: number;
    windowCursor: number;
    boundSessionId?: string;
    timeout: NodeJS.Timeout;
    waiters: Set<PendingSpawnWaiter>;
};

export type MiniAppSession = {
    traceId: string;
    id: string;
    title: string;
    requestedAppId?: string;
    state: MiniAppSessionState;
    lastError?: string;
    attached: boolean;
    createdAt: number;
    updatedAt: number;
    debugSocket?: WebSocket;
    devtoolsSocket?: WebSocket;
    windowHandle?: number;
    windowIdentity?: MiniAppWindowIdentity;
    transportPid?: number;
    closeInProgress?: boolean;
    launchId?: string;
    launchStartedAt?: number;
    launchWindowCursor?: number;
    launchAppIdConfirmed?: boolean;
    evaluationSuccesses: number;
    evaluationFailures: number;
    lastEvaluationSucceededAt?: number;
    lastEvaluationFailedAt?: number;
    messageCounter: number;
    internalCommandCounter: number;
    pendingCommands: Map<number, PendingCommand>;
    pendingContexts: Map<string, PendingContext>;
    closeWaiters: Set<CloseWaiter>;
    foregroundKeepAlive?: NodeJS.Timeout;
    appService?: AppServiceBinding;
};

export type CdpFrameTree = {
    frame?: {
        id?: string;
        url?: string;
        name?: string;
    };
    childFrames?: CdpFrameTree[];
};

export const INTERNAL_CDP_ID_BASE = 1_000_000_000;
export const INTERNAL_CDP_TIMEOUT_MS = 5_000;
export const PENDING_SPAWN_TIMEOUT_MS = 45_000;

export const bufferToHexString = (buffer: Buffer) => {
    return Array.from(buffer)
        .map((byte) => byte.toString(16).padStart(2, "0"))
        .join("");
};

export const rawDataToBuffer = (message: RawData) => {
    if (Buffer.isBuffer(message)) {
        return message;
    }

    if (Array.isArray(message)) {
        return Buffer.concat(
            message.map((chunk) =>
                Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk),
            ),
        );
    }

    return Buffer.from(message);
};

export const touchSession = (session: MiniAppSession) => {
    session.updatedAt = Date.now();
};

const getSessionId = (appid?: string) => {
    const normalizedAppId = appid?.trim() ?? "";
    return normalizedAppId || randomUUID();
};

export const createSession = (appid?: string): MiniAppSession => ({
    traceId: randomUUID(),
    id: getSessionId(appid),
    title: appid || "miniapp",
    requestedAppId: appid,
    state: "bootstrapping",
    attached: false,
    createdAt: Date.now(),
    updatedAt: Date.now(),
    messageCounter: 0,
    internalCommandCounter: INTERNAL_CDP_ID_BASE,
    evaluationSuccesses: 0,
    evaluationFailures: 0,
    pendingCommands: new Map(),
    pendingContexts: new Map(),
    closeWaiters: new Set(),
});

export const flattenFrameTree = (tree?: CdpFrameTree): CdpFrameTree["frame"][] => {
    if (!tree || !tree.frame) {
        return [];
    }

    return [
        tree.frame,
        ...((tree.childFrames || []).flatMap((childTree) =>
            flattenFrameTree(childTree),
        )),
    ];
};

export const serializeSession = (options: CliOptions, session: MiniAppSession) => ({
    traceId: session.traceId,
    id: session.id,
    appid: session.requestedAppId ?? session.id,
    requestedAppId: session.requestedAppId ?? null,
    state: session.state,
    lastError: session.lastError ?? null,
    windowHandle:
        session.windowHandle === undefined
            ? null
            : `0x${session.windowHandle.toString(16)}`,
    transportPid: session.transportPid ?? null,
    windowIdentityVerified: session.windowIdentity !== undefined,
    evaluationSuccesses: session.evaluationSuccesses,
    evaluationFailures: session.evaluationFailures,
    lastEvaluationSucceededAt:
        session.lastEvaluationSucceededAt === undefined
            ? null
            : new Date(session.lastEvaluationSucceededAt).toISOString(),
    lastEvaluationFailedAt:
        session.lastEvaluationFailedAt === undefined
            ? null
            : new Date(session.lastEvaluationFailedAt).toISOString(),
    attached: session.attached,
    createdAt: new Date(session.createdAt).toISOString(),
    targetUrl:
        session.state === "ready" &&
        session.debugSocket !== undefined &&
        session.appService !== undefined
            ? `ws://127.0.0.1:${options.cdpPort}/devtools/page/${session.id}`
            : null,
});

export const buildTarget = (options: CliOptions, session: MiniAppSession) => {
    const websocketPath = `/devtools/page/${session.id}`;
    return {
        id: session.id,
        title: session.title,
        description: "",
        type: "page",
        url: "",
        devtoolsFrontendUrl:
            `/devtools/inspector.html?ws=localhost:${options.cdpPort}` +
            `${websocketPath}`,
        webSocketDebuggerUrl: `ws://localhost:${options.cdpPort}${websocketPath}`,
    };
};
