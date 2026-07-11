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
