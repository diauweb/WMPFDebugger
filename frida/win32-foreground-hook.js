const win32ForegroundHookCallbacks = [];

const findWin32Export = (moduleName, symbolName) => {
    try {
        return Module.getExportByName(moduleName, symbolName);
    } catch (error) {
        return null;
    }
};

const patchWin32WindowRecorder = () => {
    const createWindowExWPtr = findWin32Export("user32.dll", "CreateWindowExW");
    const createWindowExAPtr = findWin32Export("user32.dll", "CreateWindowExA");
    const enumWindowsPtr = findWin32Export("user32.dll", "EnumWindows");
    const getWindowThreadProcessIdPtr = findWin32Export(
        "user32.dll",
        "GetWindowThreadProcessId",
    );

    if (!createWindowExWPtr && !createWindowExAPtr) {
        send("[hook] win32 window recorder skipped: CreateWindowEx unavailable");
        return;
    }

    const WS_CHILD = 0x40000000;
    const NULL_HWND = ptr("0");
    const currentPid = Process.id;

    const readWindowString = (value, wide) => {
        if (!value || value.isNull()) {
            return null;
        }

        const numericValue = value.toUInt32();
        if (numericValue > 0 && numericValue <= 0xffff) {
            return `#${numericValue}`;
        }

        try {
            return wide ? value.readUtf16String() : value.readCString();
        } catch (error) {
            return "<unreadable>";
        }
    };

    const emitRecordedWindow = (
        event,
        hwnd,
        apiName,
        parentHwnd,
        details = {},
    ) => {
        send({
            source: "win32-window-recorder",
            event,
            api: apiName,
            hwnd: hwnd.toString(),
            pid: currentPid,
            parentHwnd: parentHwnd.toString(),
            ...details,
        });
    };

    const attachCreateWindowHook = (targetPtr, apiName, wide) => {
        if (!targetPtr) {
            return;
        }

        Interceptor.attach(targetPtr, {
            onEnter(args) {
                this.exStyle = args[0].toUInt32();
                this.className = readWindowString(args[1], wide);
                this.windowName = readWindowString(args[2], wide);
                this.parentHwnd = args[8];
                this.style = args[3].toUInt32();
                this.threadId = Process.getCurrentThreadId();
            },
            onLeave(retval) {
                if (retval.isNull() || (this.style & WS_CHILD) !== 0) {
                    return;
                }

                emitRecordedWindow(
                    "created",
                    retval,
                    apiName,
                    this.parentHwnd,
                    {
                        threadId: this.threadId,
                        className: this.className,
                        windowName: this.windowName,
                        style: `0x${this.style.toString(16)}`,
                        exStyle: `0x${this.exStyle.toString(16)}`,
                    },
                );
            },
        });
    };

    attachCreateWindowHook(createWindowExWPtr, "CreateWindowExW", true);
    attachCreateWindowHook(createWindowExAPtr, "CreateWindowExA", false);

    if (enumWindowsPtr && getWindowThreadProcessIdPtr) {
        const enumWindows = new NativeFunction(enumWindowsPtr, "bool", [
            "pointer",
            "pointer",
        ]);
        const getWindowThreadProcessId = new NativeFunction(
            getWindowThreadProcessIdPtr,
            "uint",
            ["pointer", "pointer"],
        );
        const enumProc = new NativeCallback(
            (hwnd) => {
                const pidOut = Memory.alloc(4);
                const threadId = getWindowThreadProcessId(hwnd, pidOut);
                if (pidOut.readU32() === currentPid) {
                    emitRecordedWindow(
                        "observed",
                        hwnd,
                        "EnumWindows",
                        NULL_HWND,
                        { threadId },
                    );
                }
                return true;
            },
            "bool",
            ["pointer", "pointer"],
        );
        win32ForegroundHookCallbacks.push(enumProc);
        enumWindows(enumProc, NULL_HWND);
    }

    send("[hook] Win32 window recorder installed");
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
            if (!isCurrentProcessWindow(hwnd)) {
                return true;
            }

            if (enumFirstProcessWindow.isNull()) {
                enumFirstProcessWindow = hwnd;
            }

            if (isVisibleForegroundCandidate(hwnd)) {
                enumFirstVisibleWindow = hwnd;
                return false;
            }

            return true;
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
        if (isCurrentProcessWindow(retval)) {
            cachedHwnd = retval;
            return;
        }

        const spoofHwnd = resolveSpoofHwnd();
        if (spoofHwnd.isNull()) {
            return;
        }

        retval.replace(spoofHwnd);
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
                this.guiThreadInfo = args[1];
            },
            onLeave(retval) {
                if (retval.toInt32() === 0 || this.guiThreadInfo.isNull()) {
                    return;
                }

                const spoofHwnd = resolveSpoofHwnd();
                if (spoofHwnd.isNull()) {
                    return;
                }

                const hwndActivePtr = this.guiThreadInfo.add(8);
                const hwndFocusPtr = this.guiThreadInfo.add(16);
                const hwndActive = hwndActivePtr.readPointer();
                const hwndFocus = hwndFocusPtr.readPointer();

                if (!isCurrentProcessWindow(hwndActive)) {
                    hwndActivePtr.writePointer(spoofHwnd);
                }
                if (!isCurrentProcessWindow(hwndFocus)) {
                    hwndFocusPtr.writePointer(spoofHwnd);
                }
            },
        });
    }

    send("[hook] Win32 foreground/focus spoof installed");
};
