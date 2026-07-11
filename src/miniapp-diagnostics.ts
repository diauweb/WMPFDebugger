import { Logger } from "./logger";

type MiniAppDiagnosticValue =
    | null
    | boolean
    | number
    | string
    | MiniAppDiagnosticValue[]
    | { [key: string]: MiniAppDiagnosticValue };

type MiniAppDiagnosticEntry = {
    formatVersion: 1;
    seq: number;
    at: string;
    event: string;
    details: MiniAppDiagnosticValue;
};

const MAX_DIAGNOSTIC_ENTRIES = 300;
const entries: MiniAppDiagnosticEntry[] = [];
let sequence = 0;

const ANSI = {
    reset: "\u001b[0m",
    bold: "\u001b[1m",
    dim: "\u001b[2m",
    red: "\u001b[31m",
    green: "\u001b[32m",
    yellow: "\u001b[33m",
    blue: "\u001b[34m",
    magenta: "\u001b[35m",
    cyan: "\u001b[36m",
    gray: "\u001b[90m",
} as const;

type HumanColor = keyof Omit<typeof ANSI, "reset" | "bold" | "dim">;

const useColor =
    process.env.NO_COLOR === undefined &&
    (process.stdout.isTTY || process.env.FORCE_COLOR === "1");

const paint = (value: string, color: HumanColor, bold = false) =>
    useColor
        ? `${bold ? ANSI.bold : ""}${ANSI[color]}${value}${ANSI.reset}`
        : value;

const asRecord = (value: MiniAppDiagnosticValue | undefined) =>
    value !== null && typeof value === "object" && !Array.isArray(value)
        ? value
        : {};

const readString = (
    details: Record<string, MiniAppDiagnosticValue>,
    key: string,
) => {
    const value = details[key];
    return typeof value === "string" ? value : undefined;
};

const readNumber = (
    details: Record<string, MiniAppDiagnosticValue>,
    key: string,
) => {
    const value = details[key];
    return typeof value === "number" ? value : undefined;
};

const shortId = (value?: string) =>
    value && value.length > 12 ? value.slice(0, 8) : value;

const errorMessage = (details: Record<string, MiniAppDiagnosticValue>) => {
    const error = asRecord(details.error);
    return (
        readString(error, "message") ??
        readString(details, "reason") ??
        readString(details, "error")
    );
};

type HumanDiagnostic = {
    label: string;
    color: HumanColor;
    title: string;
    message?: string;
    dim?: boolean;
};

const formatHumanDiagnostic = (
    event: string,
    value: MiniAppDiagnosticValue,
): HumanDiagnostic | undefined => {
    const details = asRecord(value);
    const appid =
        readString(details, "appid") ??
        readString(details, "resolvedAppId") ??
        readString(details, "requestedAppId");
    const traceId = shortId(readString(details, "traceId"));
    const hwnd = readString(details, "hwnd");

    switch (event) {
        case "launch_registered":
            return {
                label: "LAUNCH",
                color: "blue",
                title: "Launch requested",
                message: appid,
            };
        case "launch_dispatched":
            return {
                label: "SEND",
                color: "cyan",
                title: "Launch sent to WeChat",
                message: appid,
            };
        case "launch_ready":
        case "bootstrap_ready":
            return {
                label: "OK",
                color: "green",
                title: "Miniapp ready",
                message: [appid, traceId && `attachment ${traceId}`]
                    .filter(Boolean)
                    .join("  "),
            };
        case "launch_rejected":
        case "launch_not_ready":
            return {
                label: "WAIT",
                color: "yellow",
                title: "Miniapp did not attach",
                message: [appid, errorMessage(details)]
                    .filter(Boolean)
                    .join(" - "),
            };
        case "launch_dispatch_failed":
            return {
                label: "FAIL",
                color: "red",
                title: "Could not send launch",
                message: [appid, errorMessage(details)]
                    .filter(Boolean)
                    .join(" - "),
            };
        case "launch_window_retained":
            return {
                label: "RETAIN",
                color: "yellow",
                title: "Running window retained for recovery",
                message: `${appid ?? "unknown app"}  ${hwnd ?? "unknown HWND"}  - explicit close required`,
            };
        case "launch_window_retention_skipped":
            return {
                label: "WARN",
                color: "yellow",
                title: "Could not safely identify launched window",
                message: [appid, readString(details, "reason")]
                    .filter(Boolean)
                    .join(" - "),
            };
        case "socket_connected":
            return {
                label: "LINK",
                color: "gray",
                title: "Debug attachment connected",
                message: traceId,
                dim: true,
            };
        case "appid_observed":
            return {
                label: "APP",
                color: "cyan",
                title: "Attachment identified",
                message: [appid, traceId].filter(Boolean).join("  "),
            };
        case "attachment_candidate_ready":
            return {
                label: "ALT",
                color: "cyan",
                title: "Alternate attachment ready",
                message: [appid, shortId(readString(details, "candidateTraceId"))]
                    .filter(Boolean)
                    .join("  "),
            };
        case "evaluate_attachment_attempt":
            return {
                label: "TRY",
                color: "gray",
                title: "Testing attachment",
                message: [appid, traceId].filter(Boolean).join("  "),
                dim: true,
            };
        case "attachment_evaluate_succeeded":
            return {
                label: "OK",
                color: "green",
                title: "Attachment works",
                message: traceId,
            };
        case "attachment_evaluate_failed":
            return {
                label: "NEXT",
                color: "yellow",
                title: "Attachment failed; trying another",
                message: [traceId, errorMessage(details)]
                    .filter(Boolean)
                    .join(" - "),
            };
        case "attachment_promoted":
            return {
                label: "SELECT",
                color: "magenta",
                title: "Selected working attachment",
                message: [appid, shortId(readString(details, "candidateTraceId"))]
                    .filter(Boolean)
                    .join("  "),
            };
        case "bootstrap_failed":
            return {
                label: "WARN",
                color: "yellow",
                title: "Attachment bootstrap failed",
                message: [traceId, errorMessage(details)]
                    .filter(Boolean)
                    .join(" - "),
            };
        case "hwnd_proof_verified":
            return {
                label: "HWND",
                color: "green",
                title: "Window identity verified",
                message: [appid, hwnd].filter(Boolean).join("  "),
            };
        case "hwnd_candidates_evaluated": {
            const reason = readString(details, "reason");
            if (reason === "create_event_absent") {
                return undefined;
            }
            const candidateCount = readNumber(details, "candidateCount") ?? 0;
            const eligibleCount = readNumber(details, "eligibleCount") ?? 0;
            return {
                label: eligibleCount === 1 ? "MATCH" : "CHECK",
                color: eligibleCount === 1 ? "green" : "yellow",
                title:
                    eligibleCount === 1
                        ? "Found exact window candidate"
                        : "Window candidates remain ambiguous",
                message: `${candidateCount} observed, ${eligibleCount} exact  - ${reason ?? "unknown reason"}`,
            };
        }
        case "close_requested":
            return {
                label: "CLOSE",
                color: "yellow",
                title: "Close requested",
                message: [appid, hwnd].filter(Boolean).join("  "),
            };
        case "close_result": {
            const complete = details.cleanupComplete === true;
            return {
                label: complete ? "OK" : "STOP",
                color: complete ? "green" : "red",
                title: complete ? "Miniapp closed" : "Close was refused safely",
                message: [appid, errorMessage(details)]
                    .filter(Boolean)
                    .join(" - "),
            };
        }
        case "close_revalidation": {
            const outcome = readString(details, "outcome");
            if (outcome === "verified") {
                return {
                    label: "VERIFY",
                    color: "green",
                    title: "Close target revalidated",
                    message: hwnd,
                };
            }
            if (outcome === "rejected") {
                return {
                    label: "SAFE",
                    color: "yellow",
                    title: "Unsafe close prevented",
                    message: readString(details, "reason"),
                };
            }
            return undefined;
        }
        case "frida_attached":
            return {
                label: "FRIDA",
                color: "green",
                title: "Window observer attached",
                message: `PID ${readNumber(details, "pid") ?? "?"}`,
            };
        case "frida_window_created":
            return {
                label: "HWND",
                color: "cyan",
                title: "Window candidate observed",
                message: [
                    readString(details, "hwnd"),
                    readString(details, "evidence"),
                ]
                    .filter(Boolean)
                    .join("  "),
            };
        case "frida_window_lifecycle":
            return {
                label: "WINDOW",
                color:
                    readString(details, "event") === "destroyed"
                        ? "magenta"
                        : "cyan",
                title:
                    readString(details, "event") === "destroyed"
                        ? "Window destroyed"
                        : "Window shown",
                message: readString(details, "hwnd"),
            };
        case "frida_script_error":
        case "frida_detached":
        case "frida_watchdog_error":
            return {
                label: "ERROR",
                color: "red",
                title: "Window observer needs attention",
                message: errorMessage(details),
            };
        default:
            return undefined;
    }
};

const printHumanDiagnostic = (
    logger: Logger,
    event: string,
    details: MiniAppDiagnosticValue,
) => {
    const formatted = formatHumanDiagnostic(event, details);
    if (!formatted) {
        return;
    }
    const prefix = paint(
        `${formatted.label.padEnd(7)} ${formatted.title}`,
        formatted.color,
        true,
    );
    const message = formatted.message
        ? formatted.dim && useColor
            ? `${ANSI.dim}${formatted.message}${ANSI.reset}`
            : formatted.message
        : "";
    logger.info(`[miniapp] ${prefix}${message ? `  ${message}` : ""}`);
};

const truncate = (value: string, maxLength = 1_000) =>
    value.length <= maxLength
        ? value
        : `${value.slice(0, maxLength)}...[truncated]`;

const toDiagnosticValue = (value: unknown): MiniAppDiagnosticValue => {
    if (value === undefined || value === null) {
        return null;
    }
    if (
        typeof value === "boolean" ||
        typeof value === "number" ||
        typeof value === "string"
    ) {
        return typeof value === "string" ? truncate(value) : value;
    }
    if (typeof value === "bigint") {
        return `0x${value.toString(16)}`;
    }
    if (value instanceof Error) {
        return {
            name: value.name,
            message: truncate(value.message),
        };
    }
    if (Array.isArray(value)) {
        return value.map(toDiagnosticValue);
    }
    if (typeof value === "object") {
        const normalized: Record<string, MiniAppDiagnosticValue> = {};
        for (const [key, nestedValue] of Object.entries(value)) {
            normalized[key] = toDiagnosticValue(nestedValue);
        }
        return normalized;
    }
    return truncate(String(value));
};

const emitMiniAppDiagnostic = (
    logger: Logger,
    event: string,
    details: unknown = {},
) => {
    const entry: MiniAppDiagnosticEntry = {
        formatVersion: 1,
        seq: ++sequence,
        at: new Date().toISOString(),
        event,
        details: toDiagnosticValue(details),
    };
    entries.push(entry);
    if (entries.length > MAX_DIAGNOSTIC_ENTRIES) {
        entries.splice(0, entries.length - MAX_DIAGNOSTIC_ENTRIES);
    }
    printHumanDiagnostic(logger, event, entry.details);
    logger.info(`[miniapp-diag] ${JSON.stringify(entry)}`);
    return entry;
};

const getMiniAppDiagnosticBundle = () => ({
    formatVersion: 1,
    generatedAt: new Date().toISOString(),
    entryCount: entries.length,
    entries: entries.map((entry) => ({ ...entry })),
});

export {
    emitMiniAppDiagnostic,
    getMiniAppDiagnosticBundle,
    MiniAppDiagnosticEntry,
};
