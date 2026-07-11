// @ts-nocheck

import { dlopen, JSCallback } from "bun:ffi";

/**
 * Read-only diagnostics for relating an accepted miniapp debug socket to the
 * Windows process that owns the other end of that exact TCP connection.
 *
 * This module deliberately does not select, remember, activate, or close an
 * HWND. Its window list is evidence for a later identity decision only.
 */

type SocketEndpoint = {
    localAddress?: string;
    localPort?: number;
    remoteAddress?: string;
    remotePort?: number;
};

type Win32WindowDiagnosticOptions = {
    additionalWindowPids?: number[];
};

type TcpFamily = "ipv4" | "ipv6";

type TcpRow = {
    family: TcpFamily;
    state: number;
    localAddress: Uint8Array;
    localScopeId: number;
    localPort: number;
    remoteAddress: Uint8Array;
    remoteScopeId: number;
    remotePort: number;
    ownerPid: number;
};

type ReportedTcpRow = {
    family: TcpFamily;
    state: number;
    localAddressHex: string;
    localScopeId: number;
    localPort: number;
    remoteAddressHex: string;
    remoteScopeId: number;
    remotePort: number;
    ownerPid: number;
};

type WindowRectangle = {
    left: number;
    top: number;
    right: number;
    bottom: number;
};

type Win32WindowSnapshot = {
    hwnd: string;
    pid: number;
    tid: number;
    className: string;
    title: string;
    visible: boolean;
    iconic: boolean;
    style: string;
    exStyle: string;
    owner: string | null;
    root: string | null;
    rootOwner: string | null;
    rect: WindowRectangle | null;
};

type Win32WindowDiagnostic = {
    supported: boolean;
    observedAt: string;
    endpoint: SocketEndpoint;
    serverPid: number;
    transportPid: number | null;
    transportProcessStartTime: string | null;
    windowPids: number[];
    windowProcessStartTimes: Record<string, string | null>;
    tcp: {
        serverMatchCount: number;
        serverMatchesByFamily: Record<TcpFamily, number>;
        reverseMatchCount: number;
        reverseMatchesByFamily: Record<TcpFamily, number>;
        serverRow: ReportedTcpRow | null;
        reverseRow: ReportedTcpRow | null;
    };
    windows: Win32WindowSnapshot[];
    errors: string[];
};

type Win32WindowInspection = {
    supported: boolean;
    windowCheckCompleted: boolean;
    windowExists: boolean;
    snapshot: Win32WindowSnapshot | null;
    processStartTime: string | null;
    errors: string[];
};

const AF_INET = 2;
const AF_INET6 = 23;
const TCP_TABLE_OWNER_PID_ALL = 5;
const NO_ERROR = 0;
const ERROR_INSUFFICIENT_BUFFER = 122;
const MIB_TCP_STATE_ESTAB = 5;

const IPV4_ROW_SIZE = 24;
const IPV6_ROW_SIZE = 56;
const TABLE_HEADER_SIZE = 4;
const MAX_TABLE_GROWTH_RETRIES = 4;

const GW_OWNER = 4;
const GA_ROOT = 2;
const GA_ROOTOWNER = 3;
const GWL_STYLE = -16;
const GWL_EXSTYLE = -20;
const MAX_WINDOW_TEXT_LENGTH = 4096;
const MAX_CLASS_NAME_LENGTH = 512;
const PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

const getErrorMessage = (error: unknown) =>
    error instanceof Error ? error.message : String(error);

const normalizeEndpoint = (endpoint: SocketEndpoint): SocketEndpoint => ({
    localAddress: endpoint?.localAddress,
    localPort: endpoint?.localPort,
    remoteAddress: endpoint?.remoteAddress,
    remotePort: endpoint?.remotePort,
});

const isTcpPort = (value: unknown): value is number =>
    Number.isSafeInteger(value) && Number(value) > 0 && Number(value) <= 65_535;

const bytesEqual = (left: Uint8Array, right: Uint8Array) => {
    if (left.byteLength !== right.byteLength) {
        return false;
    }
    for (let index = 0; index < left.byteLength; index += 1) {
        if (left[index] !== right[index]) {
            return false;
        }
    }
    return true;
};

const bytesToHex = (value: Uint8Array) =>
    Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");

const reportTcpRow = (row: TcpRow | null): ReportedTcpRow | null =>
    row
        ? {
              family: row.family,
              state: row.state,
              localAddressHex: bytesToHex(row.localAddress),
              localScopeId: row.localScopeId,
              localPort: row.localPort,
              remoteAddressHex: bytesToHex(row.remoteAddress),
              remoteScopeId: row.remoteScopeId,
              remotePort: row.remotePort,
              ownerPid: row.ownerPid,
          }
        : null;

const countTcpFamilies = (rows: TcpRow[]): Record<TcpFamily, number> => ({
    ipv4: rows.filter((row) => row.family === "ipv4").length,
    ipv6: rows.filter((row) => row.family === "ipv6").length,
});

const parseTcpTable = (
    table: Uint8Array,
    returnedSize: number,
    family: TcpFamily,
): TcpRow[] => {
    const rowSize = family === "ipv4" ? IPV4_ROW_SIZE : IPV6_ROW_SIZE;
    if (returnedSize < TABLE_HEADER_SIZE || returnedSize > table.byteLength) {
        throw new Error(
            `${family} TCP table returned invalid size ${returnedSize} for ${table.byteLength}-byte buffer`,
        );
    }

    const view = new DataView(
        table.buffer,
        table.byteOffset,
        table.byteLength,
    );
    const count = view.getUint32(0, true);
    const requiredSize = TABLE_HEADER_SIZE + count * rowSize;
    if (requiredSize > returnedSize) {
        throw new Error(
            `${family} TCP table is truncated: ${count} rows need ${requiredSize} bytes, received ${returnedSize}`,
        );
    }

    const rows: TcpRow[] = [];
    for (let index = 0; index < count; index += 1) {
        const offset = TABLE_HEADER_SIZE + index * rowSize;
        if (family === "ipv4") {
            rows.push({
                family,
                state: view.getUint32(offset, true),
                localAddress: table.slice(offset + 4, offset + 8),
                localScopeId: 0,
                localPort: view.getUint16(offset + 8, false),
                remoteAddress: table.slice(offset + 12, offset + 16),
                remoteScopeId: 0,
                remotePort: view.getUint16(offset + 16, false),
                ownerPid: view.getUint32(offset + 20, true),
            });
            continue;
        }

        // MIB_TCP6ROW_OWNER_PID stores both scope IDs in network byte order.
        rows.push({
            family,
            state: view.getUint32(offset + 48, true),
            localAddress: table.slice(offset, offset + 16),
            localScopeId: view.getUint32(offset + 16, false),
            localPort: view.getUint16(offset + 20, false),
            remoteAddress: table.slice(offset + 24, offset + 40),
            remoteScopeId: view.getUint32(offset + 40, false),
            remotePort: view.getUint16(offset + 44, false),
            ownerPid: view.getUint32(offset + 52, true),
        });
    }
    return rows;
};

const readTcpTable = (
    getExtendedTcpTable: (...args: unknown[]) => number,
    familyNumber: number,
    family: TcpFamily,
): TcpRow[] => {
    const size = new Uint32Array(1);
    const initialStatus = Number(
        getExtendedTcpTable(
            null,
            size,
            0,
            familyNumber,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        ),
    );
    if (
        initialStatus !== NO_ERROR &&
        initialStatus !== ERROR_INSUFFICIENT_BUFFER
    ) {
        throw new Error(
            `GetExtendedTcpTable(${family}) size query failed with ${initialStatus}`,
        );
    }
    if (size[0] === 0) {
        return [];
    }

    for (
        let attempt = 0;
        attempt < MAX_TABLE_GROWTH_RETRIES;
        attempt += 1
    ) {
        const capacity = size[0];
        const tableWords = new Uint32Array(Math.ceil(capacity / 4));
        const table = new Uint8Array(
            tableWords.buffer,
            tableWords.byteOffset,
            tableWords.byteLength,
        );
        size[0] = capacity;
        const status = Number(
            getExtendedTcpTable(
                tableWords,
                size,
                0,
                familyNumber,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            ),
        );
        if (status === ERROR_INSUFFICIENT_BUFFER) {
            continue;
        }
        if (status !== NO_ERROR) {
            throw new Error(
                `GetExtendedTcpTable(${family}) failed with ${status}`,
            );
        }
        return parseTcpTable(table, size[0], family);
    }

    throw new Error(
        `GetExtendedTcpTable(${family}) kept growing during ${MAX_TABLE_GROWTH_RETRIES} reads`,
    );
};

const isExactReverse = (server: TcpRow, candidate: TcpRow) =>
    candidate.family === server.family &&
    candidate.state === MIB_TCP_STATE_ESTAB &&
    candidate.localPort === server.remotePort &&
    candidate.remotePort === server.localPort &&
    candidate.localScopeId === server.remoteScopeId &&
    candidate.remoteScopeId === server.localScopeId &&
    bytesEqual(candidate.localAddress, server.remoteAddress) &&
    bytesEqual(candidate.remoteAddress, server.localAddress);

const handleToBigInt = (value: unknown): bigint => {
    if (value === null || value === undefined) {
        return 0n;
    }
    if (typeof value === "bigint") {
        return BigInt.asUintN(64, value);
    }
    if (typeof value === "number") {
        return value > 0 ? BigInt(Math.trunc(value)) : 0n;
    }
    try {
        return BigInt.asUintN(64, BigInt(value as never));
    } catch {
        return 0n;
    }
};

const formatHandle = (value: unknown): string | null => {
    const handle = handleToBigInt(value);
    return handle === 0n ? null : `0x${handle.toString(16)}`;
};

const formatStyle = (value: unknown) => {
    const normalized =
        typeof value === "bigint"
            ? BigInt.asUintN(32, value)
            : BigInt.asUintN(32, BigInt(Math.trunc(Number(value))));
    return `0x${normalized.toString(16).padStart(8, "0")}`;
};

const decodeWideBuffer = (buffer: Uint16Array, written: number) => {
    if (written <= 0) {
        return "";
    }
    return Buffer.from(
        buffer.buffer,
        buffer.byteOffset,
        Math.min(written, buffer.length) * 2,
    ).toString("utf16le");
};

const readWindowText = (symbols: Record<string, Function>, hwnd: unknown) => {
    const reportedLength = Math.max(
        0,
        Number(symbols.GetWindowTextLengthW(hwnd)),
    );
    const capacity = Math.min(reportedLength + 1, MAX_WINDOW_TEXT_LENGTH + 1);
    const buffer = new Uint16Array(Math.max(capacity, 1));
    const written = Number(
        symbols.GetWindowTextW(hwnd, buffer, buffer.length),
    );
    return decodeWideBuffer(buffer, written);
};

const readClassName = (symbols: Record<string, Function>, hwnd: unknown) => {
    const buffer = new Uint16Array(MAX_CLASS_NAME_LENGTH + 1);
    const written = Number(symbols.GetClassNameW(hwnd, buffer, buffer.length));
    return decodeWideBuffer(buffer, written);
};

const readWindowRect = (
    symbols: Record<string, Function>,
    hwnd: unknown,
): WindowRectangle | null => {
    const rect = new Int32Array(4);
    if (!symbols.GetWindowRect(hwnd, rect)) {
        return null;
    }
    return {
        left: rect[0],
        top: rect[1],
        right: rect[2],
        bottom: rect[3],
    };
};

const inventoryTopLevelWindows = (
    symbols: Record<string, Function>,
    JSCallback: new (...args: unknown[]) => {
        ptr: unknown;
        close: () => void;
    },
    targetPids: ReadonlySet<number>,
): { windows: Win32WindowSnapshot[]; errors: string[] } => {
    const windows: Win32WindowSnapshot[] = [];
    const errors: string[] = [];

    const callback = new JSCallback(
        (hwnd: unknown) => {
            try {
                const pid = new Uint32Array(1);
                const tid = Number(symbols.GetWindowThreadProcessId(hwnd, pid));
                if (!targetPids.has(pid[0])) {
                    return 1;
                }

                const hwndText = formatHandle(hwnd);
                if (hwndText === null) {
                    errors.push("EnumWindows returned a null HWND");
                    return 1;
                }

                windows.push({
                    hwnd: hwndText,
                    pid: pid[0],
                    tid,
                    className: readClassName(symbols, hwnd),
                    title: readWindowText(symbols, hwnd),
                    visible: Boolean(symbols.IsWindowVisible(hwnd)),
                    iconic: Boolean(symbols.IsIconic(hwnd)),
                    style: formatStyle(
                        symbols.GetWindowLongPtrW(hwnd, GWL_STYLE),
                    ),
                    exStyle: formatStyle(
                        symbols.GetWindowLongPtrW(hwnd, GWL_EXSTYLE),
                    ),
                    owner: formatHandle(symbols.GetWindow(hwnd, GW_OWNER)),
                    root: formatHandle(symbols.GetAncestor(hwnd, GA_ROOT)),
                    rootOwner: formatHandle(
                        symbols.GetAncestor(hwnd, GA_ROOTOWNER),
                    ),
                    rect: readWindowRect(symbols, hwnd),
                });
            } catch (error) {
                errors.push(
                    `failed to inspect ${formatHandle(hwnd) ?? "unknown HWND"}: ${getErrorMessage(error)}`,
                );
            }
            return 1;
        },
        {
            args: ["ptr", "i64"],
            returns: "i32",
        },
    );

    try {
        if (!symbols.EnumWindows(callback.ptr, 0n)) {
            errors.push("EnumWindows returned failure");
        }
    } catch (error) {
        errors.push(`EnumWindows failed: ${getErrorMessage(error)}`);
    } finally {
        callback.close();
    }

    return { windows, errors };
};

const openUser32 = () =>
    dlopen("user32.dll", {
        EnumWindows: {
            args: ["ptr", "i64"],
            returns: "i32",
        },
        GetWindowThreadProcessId: {
            args: ["ptr", "ptr"],
            returns: "u32",
        },
        IsWindow: {
            args: ["u64"],
            returns: "i32",
        },
        IsWindowVisible: {
            args: ["ptr"],
            returns: "i32",
        },
        IsIconic: {
            args: ["ptr"],
            returns: "i32",
        },
        GetWindowTextLengthW: {
            args: ["ptr"],
            returns: "i32",
        },
        GetWindowTextW: {
            args: ["ptr", "ptr", "i32"],
            returns: "i32",
        },
        GetClassNameW: {
            args: ["ptr", "ptr", "i32"],
            returns: "i32",
        },
        GetWindowLongPtrW: {
            args: ["ptr", "i32"],
            returns: "i64",
        },
        GetWindow: {
            args: ["ptr", "u32"],
            returns: "ptr",
        },
        GetAncestor: {
            args: ["ptr", "u32"],
            returns: "ptr",
        },
        GetWindowRect: {
            args: ["ptr", "ptr"],
            returns: "i32",
        },
    });

const readProcessStartTime = (pid: number) => {
    let kernel32: ReturnType<typeof dlopen> | null = null;
    let processHandle = 0n;
    try {
        kernel32 = dlopen("kernel32.dll", {
            OpenProcess: {
                args: ["u32", "i32", "u32"],
                returns: "u64",
            },
            GetProcessTimes: {
                args: ["u64", "ptr", "ptr", "ptr", "ptr"],
                returns: "i32",
            },
            CloseHandle: {
                args: ["u64"],
                returns: "i32",
            },
        });
        processHandle = handleToBigInt(
            kernel32.symbols.OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION,
                0,
                pid,
            ),
        );
        if (processHandle === 0n) {
            throw new Error(`OpenProcess(${pid}) failed`);
        }

        const creation = new Uint32Array(2);
        const exit = new Uint32Array(2);
        const kernel = new Uint32Array(2);
        const user = new Uint32Array(2);
        if (
            !kernel32.symbols.GetProcessTimes(
                processHandle,
                creation,
                exit,
                kernel,
                user,
            )
        ) {
            throw new Error(`GetProcessTimes(${pid}) failed`);
        }

        return (
            (BigInt(creation[1]) << 32n) | BigInt(creation[0])
        ).toString();
    } finally {
        if (kernel32 && processHandle !== 0n) {
            kernel32.symbols.CloseHandle(processHandle);
        }
        kernel32?.close?.();
    }
};

/**
 * Correlate a connected socket with its exact reversed TCP row and inventory
 * top-level windows owned by that transport PID. Ambiguity returns no PID and
 * no HWND inventory; it never guesses.
 */
const diagnoseWin32WindowIdentity = async (
    socket: SocketEndpoint,
    options: Win32WindowDiagnosticOptions = {},
): Promise<Win32WindowDiagnostic> => {
    const endpoint = normalizeEndpoint(socket);
    const result: Win32WindowDiagnostic = {
        supported: process.platform === "win32" && process.arch === "x64",
        observedAt: new Date().toISOString(),
        endpoint,
        serverPid: process.pid,
        transportPid: null,
        transportProcessStartTime: null,
        windowPids: [],
        windowProcessStartTimes: {},
        tcp: {
            serverMatchCount: 0,
            serverMatchesByFamily: { ipv4: 0, ipv6: 0 },
            reverseMatchCount: 0,
            reverseMatchesByFamily: { ipv4: 0, ipv6: 0 },
            serverRow: null,
            reverseRow: null,
        },
        windows: [],
        errors: [],
    };

    if (process.platform !== "win32") {
        result.errors.push("Win32 diagnostics are unavailable on this platform");
        return result;
    }
    if (process.arch !== "x64") {
        result.errors.push("Win32 diagnostics require x64 Windows");
        return result;
    }
    if (!isTcpPort(endpoint.localPort) || !isTcpPort(endpoint.remotePort)) {
        result.errors.push("socket localPort and remotePort must be valid TCP ports");
        return result;
    }

    let rows: TcpRow[];
    let iphlpapi: ReturnType<typeof dlopen> | null = null;
    try {
        iphlpapi = dlopen("iphlpapi.dll", {
            GetExtendedTcpTable: {
                args: ["ptr", "ptr", "i32", "u32", "u32", "u32"],
                returns: "u32",
            },
        });
        rows = [];
        for (const [familyNumber, family] of [
            [AF_INET, "ipv4"],
            [AF_INET6, "ipv6"],
        ] as const) {
            try {
                rows.push(
                    ...readTcpTable(
                        iphlpapi.symbols.GetExtendedTcpTable,
                        familyNumber,
                        family,
                    ),
                );
            } catch (error) {
                result.errors.push(
                    `${family} TCP owner lookup failed: ${getErrorMessage(error)}`,
                );
            }
        }
    } catch (error) {
        result.errors.push(`TCP owner lookup failed: ${getErrorMessage(error)}`);
        return result;
    } finally {
        iphlpapi?.close?.();
    }

    const serverMatches = rows.filter(
        (row) =>
            row.state === MIB_TCP_STATE_ESTAB &&
            row.ownerPid === process.pid &&
            row.localPort === endpoint.localPort &&
            row.remotePort === endpoint.remotePort,
    );
    result.tcp.serverMatchCount = serverMatches.length;
    result.tcp.serverMatchesByFamily = countTcpFamilies(serverMatches);
    if (serverMatches.length !== 1) {
        result.errors.push(
            `expected one server TCP row for the socket tuple, found ${serverMatches.length}`,
        );
        return result;
    }

    const serverRow = serverMatches[0];
    result.tcp.serverRow = reportTcpRow(serverRow);
    const reverseMatches = rows.filter(
        (row) => row !== serverRow && isExactReverse(serverRow, row),
    );
    result.tcp.reverseMatchCount = reverseMatches.length;
    result.tcp.reverseMatchesByFamily = countTcpFamilies(reverseMatches);
    if (reverseMatches.length !== 1) {
        result.errors.push(
            `expected one exactly reversed client TCP row, found ${reverseMatches.length}`,
        );
        return result;
    }

    const reverseRow = reverseMatches[0];
    result.tcp.reverseRow = reportTcpRow(reverseRow);
    result.transportPid = reverseRow.ownerPid;
    try {
        result.transportProcessStartTime = readProcessStartTime(
            result.transportPid,
        );
    } catch (error) {
        result.errors.push(
            `transport process start-time lookup failed: ${getErrorMessage(error)}`,
        );
    }

    let user32: ReturnType<typeof dlopen> | null = null;
    try {
        const windowPids = new Set<number>([result.transportPid]);
        for (const pid of options.additionalWindowPids ?? []) {
            if (Number.isSafeInteger(pid) && pid > 0) {
                windowPids.add(pid);
            }
        }
        result.windowPids = Array.from(windowPids).sort(
            (left, right) => left - right,
        );
        for (const pid of result.windowPids) {
            if (
                pid === result.transportPid &&
                result.transportProcessStartTime !== null
            ) {
                result.windowProcessStartTimes[String(pid)] =
                    result.transportProcessStartTime;
                continue;
            }
            try {
                result.windowProcessStartTimes[String(pid)] =
                    readProcessStartTime(pid);
            } catch (error) {
                result.windowProcessStartTimes[String(pid)] = null;
                result.errors.push(
                    `window-owner process start-time lookup failed for ${pid}: ${getErrorMessage(error)}`,
                );
            }
        }
        user32 = openUser32();
        const inventory = inventoryTopLevelWindows(
            user32.symbols,
            JSCallback,
            windowPids,
        );
        result.windows = inventory.windows;
        result.errors.push(...inventory.errors);
    } catch (error) {
        result.errors.push(`HWND inventory failed: ${getErrorMessage(error)}`);
    } finally {
        user32?.close?.();
    }

    return result;
};

const inspectWin32WindowIdentity = (
    handle: number | bigint,
    expectedPid: number,
): Win32WindowInspection => {
    const result: Win32WindowInspection = {
        supported: process.platform === "win32" && process.arch === "x64",
        windowCheckCompleted: false,
        windowExists: false,
        snapshot: null,
        processStartTime: null,
        errors: [],
    };
    if (process.platform !== "win32") {
        result.errors.push("Win32 diagnostics are unavailable on this platform");
        return result;
    }
    if (process.arch !== "x64") {
        result.errors.push("Win32 diagnostics require x64 Windows");
        return result;
    }

    const normalizedHandle = handleToBigInt(handle);
    if (normalizedHandle === 0n || !Number.isSafeInteger(expectedPid) || expectedPid <= 0) {
        result.errors.push("a valid HWND and expected PID are required");
        return result;
    }

    try {
        result.processStartTime = readProcessStartTime(expectedPid);
    } catch (error) {
        result.errors.push(
            `process start-time lookup failed: ${getErrorMessage(error)}`,
        );
    }

    let user32: ReturnType<typeof dlopen> | null = null;
    try {
        user32 = openUser32();
        result.windowExists = Boolean(
            user32.symbols.IsWindow(normalizedHandle),
        );
        result.windowCheckCompleted = true;
        if (!result.windowExists) {
            return result;
        }
        const inventory = inventoryTopLevelWindows(
            user32.symbols,
            JSCallback,
            new Set([expectedPid]),
        );
        result.errors.push(...inventory.errors);
        const expectedHwnd = `0x${normalizedHandle.toString(16)}`;
        const matches = inventory.windows.filter(
            (window) => window.hwnd.toLowerCase() === expectedHwnd,
        );
        if (matches.length === 1) {
            result.snapshot = matches[0];
        } else if (matches.length > 1) {
            result.errors.push(
                `expected one top-level snapshot for ${expectedHwnd}, found ${matches.length}`,
            );
        }
    } catch (error) {
        result.errors.push(`HWND inspection failed: ${getErrorMessage(error)}`);
    } finally {
        user32?.close?.();
    }

    return result;
};

export {
    diagnoseWin32WindowIdentity,
    inspectWin32WindowIdentity,
    SocketEndpoint,
    Win32WindowDiagnosticOptions,
    Win32WindowDiagnostic,
    Win32WindowInspection,
    Win32WindowSnapshot,
};
