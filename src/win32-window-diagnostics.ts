// @ts-nocheck

import { dlopen, JSCallback } from "bun:ffi";

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

type Win32WindowInspection = {
    supported: boolean;
    windowCheckCompleted: boolean;
    windowExists: boolean;
    snapshot: Win32WindowSnapshot | null;
    errors: string[];
};

const GW_OWNER = 4;
const GA_ROOT = 2;
const GA_ROOTOWNER = 3;
const GWL_STYLE = -16;
const GWL_EXSTYLE = -20;
const MAX_WINDOW_TEXT_LENGTH = 4096;
const MAX_CLASS_NAME_LENGTH = 512;

const getErrorMessage = (error: unknown) =>
    error instanceof Error ? error.message : String(error);

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

const inspectWin32WindowIdentity = (
    handle: number | bigint,
    expectedPid: number,
): Win32WindowInspection => {
    const result: Win32WindowInspection = {
        supported: process.platform === "win32" && process.arch === "x64",
        windowCheckCompleted: false,
        windowExists: false,
        snapshot: null,
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

/**
 * Synchronous snapshot of the top-level windows owned by one PID. Used to
 * capture a miniapp window at the moment its identity is known (bootstrap
 * success) instead of depending on asynchronous window-creation events.
 */
const snapshotTopLevelWindowsForPid = (
    pid: number,
): Win32WindowSnapshot[] => {
    if (
        process.platform !== "win32" ||
        process.arch !== "x64" ||
        !Number.isSafeInteger(pid) ||
        pid <= 0
    ) {
        return [];
    }

    let user32: ReturnType<typeof dlopen> | null = null;
    try {
        user32 = openUser32();
        const inventory = inventoryTopLevelWindows(
            user32.symbols,
            JSCallback,
            new Set([pid]),
        );
        return inventory.windows;
    } catch {
        return [];
    } finally {
        user32?.close?.();
    }
};

export {
    inspectWin32WindowIdentity,
    snapshotTopLevelWindowsForPid,
    Win32WindowInspection,
    Win32WindowSnapshot,
};
