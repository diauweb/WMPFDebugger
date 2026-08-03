const win32ForegroundHookCallbacks = [];

const sendHookError = (message) => {
    try {
        send({
            source: "wmpf-hook",
            event: "hook-error",
            message: String(message),
            at: Date.now(),
        });
    } catch (error) {
        // The hook must never crash the host because reporting failed.
    }
};

const findWin32Export = (moduleName, symbolName) => {
    try {
        const module = Process.findModuleByName(moduleName);
        if (!module) {
            return null;
        }
        const exportAddress = module.findExportByName(symbolName);
        return exportAddress ?? null;
    } catch (error) {
        return null;
    }
};

const patchWin32WindowRecorder = () => {
    const createWindowExWPtr = findWin32Export("user32.dll", "CreateWindowExW");
    const createWindowExAPtr = findWin32Export("user32.dll", "CreateWindowExA");
    const enumWindowsPtr = findWin32Export("user32.dll", "EnumWindows");
    const destroyWindowPtr = findWin32Export("user32.dll", "DestroyWindow");
    const showWindowPtr = findWin32Export("user32.dll", "ShowWindow");
    const setWindowTextWPtr = findWin32Export("user32.dll", "SetWindowTextW");
    const getWindowLongWPtr = findWin32Export("user32.dll", "GetWindowLongW");
    const isWindowVisiblePtr = findWin32Export(
        "user32.dll",
        "IsWindowVisible",
    );
    const getWindowThreadProcessIdPtr = findWin32Export(
        "user32.dll",
        "GetWindowThreadProcessId",
    );
    const getClassNameWPtr = findWin32Export("user32.dll", "GetClassNameW");
    const getWindowTextWPtr = findWin32Export("user32.dll", "GetWindowTextW");

    if (!createWindowExWPtr && !createWindowExAPtr) {
        send({
            source: "wmpf-hook",
            event: "hook-error",
            message: "CreateWindowEx unavailable",
            at: Date.now(),
        });
        return;
    }

    const WS_CHILD = 0x40000000;
    const NULL_HWND = ptr("0");
    const currentPid = Process.id;
    // Frida 17 does not allow `this.property` state passing in interceptor
    // callbacks, so before/after state is kept in module-level variables.
    let lastShowWindow = null;
    let lastDestroyWindow = null;
    let lastSetWindowText = null;
    const getWindowLongW = getWindowLongWPtr
        ? new NativeFunction(getWindowLongWPtr, "int", ["pointer", "int"])
        : null;
    const isWindowVisible = isWindowVisiblePtr
        ? new NativeFunction(isWindowVisiblePtr, "bool", ["pointer"])
        : null;
    const getWindowThreadProcessId = getWindowThreadProcessIdPtr
        ? new NativeFunction(getWindowThreadProcessIdPtr, "uint", [
              "pointer",
              "pointer",
          ])
        : null;
    const getClassNameW = getClassNameWPtr
        ? new NativeFunction(getClassNameWPtr, "int", [
              "pointer",
              "pointer",
              "int",
          ])
        : null;
    const getWindowTextW = getWindowTextWPtr
        ? new NativeFunction(getWindowTextWPtr, "int", [
              "pointer",
              "pointer",
              "int",
          ])
        : null;

    const readTopLevelStyle = (hwnd) => {
        if (!getWindowLongW || !hwnd || hwnd.isNull()) {
            return null;
        }
        const style = getWindowLongW(hwnd, -16) >>> 0;
        return (style & WS_CHILD) === 0 ? style : null;
    };

    const readClassName = (hwnd) => {
        if (!getClassNameW || !hwnd || hwnd.isNull()) {
            return null;
        }
        try {
            const buffer = Memory.alloc(512);
            const written = getClassNameW(hwnd, buffer, 256);
            return written > 0 ? buffer.readUtf16String() : null;
        } catch (error) {
            return null;
        }
    };

    const readWindowTitle = (hwnd) => {
        if (!getWindowTextW || !hwnd || hwnd.isNull()) {
            return "";
        }
        try {
            const buffer = Memory.alloc(1024);
            const written = getWindowTextW(hwnd, buffer, 512);
            return written > 0 ? buffer.readUtf16String() : "";
        } catch (error) {
            return "";
        }
    };

    const readWindowTid = (hwnd) => {
        if (!getWindowThreadProcessId || !hwnd || hwnd.isNull()) {
            return 0;
        }
        try {
            const pidOut = Memory.alloc(4);
            return getWindowThreadProcessId(hwnd, pidOut);
        } catch (error) {
            return 0;
        }
    };

    const sendWindowEvent = (event, hwnd, details = {}) => {
        send({
            source: "wmpf-hook",
            event,
            hwnd: hwnd.toString(),
            pid: currentPid,
            at: Date.now(),
            ...details,
        });
    };

    const attachCreateWindowHook = (targetPtr, apiName) => {
        if (!targetPtr) {
            return;
        }

        Interceptor.attach(targetPtr, {
            onLeave(retval) {
                try {
                    if (retval.isNull()) {
                        return;
                    }
                    const style = readTopLevelStyle(retval);
                    if (style === null) {
                        return;
                    }

                    sendWindowEvent("window-created", retval, {
                        tid: readWindowTid(retval),
                        className: readClassName(retval) ?? "",
                        title: readWindowTitle(retval),
                        visible: isWindowVisible
                            ? Boolean(isWindowVisible(retval))
                            : false,
                        style: `0x${style.toString(16)}`,
                        parentHwnd: "",
                    });
                } catch (error) {
                    sendWindowEvent("hook-error", NULL_HWND, {
                        message: `${apiName} onLeave: ${error}`,
                    });
                }
            },
        });
    };

    attachCreateWindowHook(createWindowExWPtr, "CreateWindowExW");
    attachCreateWindowHook(createWindowExAPtr, "CreateWindowExA");

    if (showWindowPtr && isWindowVisible) {
        Interceptor.attach(showWindowPtr, {
            onEnter(args) {
                try {
                    const hwnd = args[0];
                    lastShowWindow = {
                        hwnd: hwnd.toString(),
                        style: readTopLevelStyle(hwnd),
                        visibleBefore: isWindowVisible
                            ? Boolean(isWindowVisible(hwnd))
                            : false,
                    };
                } catch (error) {
                    sendWindowEvent("hook-error", NULL_HWND, {
                        message: `ShowWindow onEnter: ${error}`,
                    });
                }
            },
            onLeave() {
                try {
                    const state = lastShowWindow;
                    if (!state || state.style === null) {
                        return;
                    }
                    const hwnd = ptr(state.hwnd);
                    const visibleAfter = Boolean(isWindowVisible(hwnd));
                    if (!visibleAfter && !state.visibleBefore) {
                        return;
                    }
                    sendWindowEvent("window-shown", hwnd, {
                        tid: readWindowTid(hwnd),
                        className: readClassName(hwnd) ?? "",
                        title: readWindowTitle(hwnd),
                        visibleBefore: state.visibleBefore,
                        visibleAfter,
                    });
                } catch (error) {
                    sendWindowEvent("hook-error", NULL_HWND, {
                        message: `ShowWindow onLeave: ${error}`,
                    });
                }
            },
        });
    }

    if (destroyWindowPtr) {
        Interceptor.attach(destroyWindowPtr, {
            onEnter(args) {
                try {
                    lastDestroyWindow = {
                        hwnd: args[0].toString(),
                        style: readTopLevelStyle(args[0]),
                        tid: Process.getCurrentThreadId(),
                    };
                } catch (error) {
                    sendWindowEvent("hook-error", NULL_HWND, {
                        message: `DestroyWindow onEnter: ${error}`,
                    });
                }
            },
            onLeave(retval) {
                try {
                    const state = lastDestroyWindow;
                    if (!state || state.style === null) {
                        return;
                    }
                    sendWindowEvent(
                        "window-destroyed",
                        ptr(state.hwnd),
                        {
                            tid: state.tid,
                            success: Boolean(retval.toInt32()),
                        },
                    );
                } catch (error) {
                    sendWindowEvent("hook-error", NULL_HWND, {
                        message: `DestroyWindow onLeave: ${error}`,
                    });
                }
            },
        });
    }

    if (setWindowTextWPtr) {
        Interceptor.attach(setWindowTextWPtr, {
            onEnter(args) {
                try {
                    lastSetWindowText = {
                        hwnd: args[0].toString(),
                        title: args[1].isNull()
                            ? ""
                            : args[1].readUtf16String(),
                        style: readTopLevelStyle(args[0]),
                    };
                } catch (error) {
                    sendWindowEvent("hook-error", NULL_HWND, {
                        message: `SetWindowTextW onEnter: ${error}`,
                    });
                }
            },
            onLeave() {
                try {
                    const state = lastSetWindowText;
                    if (!state || state.style === null) {
                        return;
                    }
                    sendWindowEvent(
                        "window-title-changed",
                        ptr(state.hwnd),
                        {
                            tid: Process.getCurrentThreadId(),
                            title: state.title ?? "",
                        },
                    );
                } catch (error) {
                    sendWindowEvent("hook-error", NULL_HWND, {
                        message: `SetWindowTextW onLeave: ${error}`,
                    });
                }
            },
        });
    }

    if (enumWindowsPtr && getWindowThreadProcessId) {
        const enumWindows = new NativeFunction(enumWindowsPtr, "bool", [
            "pointer",
            "pointer",
        ]);
        const snapshot = [];
        const enumProc = new NativeCallback(
            (hwnd) => {
                try {
                    const pidOut = Memory.alloc(4);
                    const threadId = getWindowThreadProcessId(hwnd, pidOut);
                    if (pidOut.readU32() === currentPid) {
                        snapshot.push({
                            hwnd: hwnd.toString(),
                            tid: threadId,
                            className: readClassName(hwnd) ?? "",
                            title: readWindowTitle(hwnd),
                            visible: isWindowVisible
                                ? Boolean(isWindowVisible(hwnd))
                                : false,
                        });
                    }
                } catch (error) {
                    sendWindowEvent("hook-error", NULL_HWND, {
                        message: `EnumWindows callback: ${error}`,
                    });
                }
                return 1;
            },
            "bool",
            ["pointer", "pointer"],
        );
        win32ForegroundHookCallbacks.push(enumProc);
        enumWindows(enumProc, NULL_HWND);
        send({
            source: "wmpf-hook",
            event: "windows-snapshot",
            pid: currentPid,
            at: Date.now(),
            windows: snapshot,
        });
    }

    send({
        source: "wmpf-hook",
        event: "recorder-installed",
        at: Date.now(),
    });
};

const patchWin32ForegroundState = () => {
    const getForegroundWindowPtr = findWin32Export("user32.dll", "GetForegroundWindow");
    const getActiveWindowPtr = findWin32Export("user32.dll", "GetActiveWindow");
    const getFocusPtr = findWin32Export("user32.dll", "GetFocus");
    const getGuiThreadInfoPtr = findWin32Export("user32.dll", "GetGUIThreadInfo");
    const enumWindowsPtr = findWin32Export("user32.dll", "EnumWindows");
    const getWindowThreadProcessIdPtr = findWin32Export(
        "user32.dll",
        "GetWindowThreadProcessId",
    );
    const isWindowPtr = findWin32Export("user32.dll", "IsWindow");
    const isWindowVisiblePtr = findWin32Export("user32.dll", "IsWindowVisible");
    const isIconicPtr = findWin32Export("user32.dll", "IsIconic");

    if (
        !getForegroundWindowPtr ||
        !getActiveWindowPtr ||
        !getFocusPtr ||
        !enumWindowsPtr ||
        !getWindowThreadProcessIdPtr ||
        !isWindowPtr
    ) {
        send("[hook] user32 foreground spoof skipped: required exports unavailable");
        return;
    }

    const NULL_HWND = ptr("0");
    const currentPid = Process.id;
    const enumWindows = new NativeFunction(enumWindowsPtr, "bool", [
        "pointer",
        "pointer",
    ]);
    const getWindowThreadProcessId = new NativeFunction(
        getWindowThreadProcessIdPtr,
        "uint",
        ["pointer", "pointer"],
    );
    const isWindow = new NativeFunction(isWindowPtr, "bool", ["pointer"]);
    const isWindowVisible = isWindowVisiblePtr
        ? new NativeFunction(isWindowVisiblePtr, "bool", ["pointer"])
        : null;
    const isIconic = isIconicPtr
        ? new NativeFunction(isIconicPtr, "bool", ["pointer"])
        : null;

    let cachedHwnd = NULL_HWND;
    let enumFirstProcessWindow = NULL_HWND;
    let enumFirstVisibleWindow = NULL_HWND;
    let lastGuiThreadInfo = null;

    const getWindowPid = (hwnd) => {
        if (hwnd.isNull()) {
            return 0;
        }

        const pidOut = Memory.alloc(4);
        getWindowThreadProcessId(hwnd, pidOut);
        return pidOut.readU32();
    };

    const isCurrentProcessWindow = (hwnd) => {
        try {
            return !hwnd.isNull() && isWindow(hwnd) && getWindowPid(hwnd) === currentPid;
        } catch (error) {
            return false;
        }
    };

    const isVisibleForegroundCandidate = (hwnd) => {
        if (!isCurrentProcessWindow(hwnd)) {
            return false;
        }
        if (isWindowVisible && !isWindowVisible(hwnd)) {
            return false;
        }
        if (isIconic && isIconic(hwnd)) {
            return false;
        }
        return true;
    };

    const enumProc = new NativeCallback(
        (hwnd) => {
            try {
                if (!isCurrentProcessWindow(hwnd)) {
                    return 1;
                }

                if (enumFirstProcessWindow.isNull()) {
                    enumFirstProcessWindow = hwnd;
                }

                if (isVisibleForegroundCandidate(hwnd)) {
                    enumFirstVisibleWindow = hwnd;
                    return 0;
                }
            } catch (error) {
                sendHookError(`spoof enum: ${error}`);
            }
            return 1;
        },
        "bool",
        ["pointer", "pointer"],
    );
    win32ForegroundHookCallbacks.push(enumProc);

    const resolveSpoofHwnd = () => {
        if (isVisibleForegroundCandidate(cachedHwnd)) {
            return cachedHwnd;
        }

        enumFirstProcessWindow = NULL_HWND;
        enumFirstVisibleWindow = NULL_HWND;
        enumWindows(enumProc, NULL_HWND);
        cachedHwnd = enumFirstVisibleWindow.isNull()
            ? enumFirstProcessWindow
            : enumFirstVisibleWindow;
        return cachedHwnd;
    };

    const replaceWithSpoofHwnd = (retval) => {
        try {
            if (isCurrentProcessWindow(retval)) {
                cachedHwnd = retval;
                return;
            }

            const spoofHwnd = resolveSpoofHwnd();
            if (spoofHwnd.isNull()) {
                return;
            }

            retval.replace(spoofHwnd);
        } catch (error) {
            sendHookError(`spoof replace: ${error}`);
        }
    };

    Interceptor.attach(getForegroundWindowPtr, {
        onLeave(retval) {
            replaceWithSpoofHwnd(retval);
        },
    });

    Interceptor.attach(getActiveWindowPtr, {
        onLeave(retval) {
            replaceWithSpoofHwnd(retval);
        },
    });

    Interceptor.attach(getFocusPtr, {
        onLeave(retval) {
            replaceWithSpoofHwnd(retval);
        },
    });

    if (getGuiThreadInfoPtr) {
        Interceptor.attach(getGuiThreadInfoPtr, {
            onEnter(args) {
                try {
                    lastGuiThreadInfo = args[1];
                } catch (error) {
                    sendHookError(`GetGUIThreadInfo onEnter: ${error}`);
                }
            },
            onLeave(retval) {
                try {
                    const guiThreadInfo = lastGuiThreadInfo;
                    if (
                        retval.toInt32() === 0 ||
                        !guiThreadInfo ||
                        guiThreadInfo.isNull()
                    ) {
                        return;
                    }

                    const spoofHwnd = resolveSpoofHwnd();
                    if (spoofHwnd.isNull()) {
                        return;
                    }

                    const hwndActivePtr = guiThreadInfo.add(8);
                    const hwndFocusPtr = guiThreadInfo.add(16);
                    const hwndActive = hwndActivePtr.readPointer();
                    const hwndFocus = hwndFocusPtr.readPointer();

                    if (!isCurrentProcessWindow(hwndActive)) {
                        hwndActivePtr.writePointer(spoofHwnd);
                    }
                    if (!isCurrentProcessWindow(hwndFocus)) {
                        hwndFocusPtr.writePointer(spoofHwnd);
                    }
                } catch (error) {
                    sendHookError(`GetGUIThreadInfo onLeave: ${error}`);
                }
            },
        });
    }

    send("[hook] Win32 foreground/focus spoof installed");
};
