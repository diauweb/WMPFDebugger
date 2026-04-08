// @ts-nocheck
import { dlopen, ptr } from "bun:ffi";

type WeChatWindow = "main" | "login" | "none";

type WeChatStatus = {
    window: WeChatWindow;
};

type WeChatWindowHandle = {
    window: WeChatWindow;
    handle: number | null;
};

const POINTER_SIZE = 8;
const COPYDATASTRUCT_SIZE = 24;
const CBDATA_OFFSET = 8;
const LPDATA_OFFSET = 16;

const WM_COPYDATA = 0x004a;
const MINIAPP_LAUNCH_WPARAM = 0x2c96;

const MAIN_WINDOW_CLASS = "WeChatMainWndForPC";
const LOGIN_WINDOW_CLASS = "WeChatLoginWndForPC";

const user32 =
    process.platform === "win32"
        ? dlopen("user32.dll", {
              FindWindowW: {
                  args: ["ptr", "ptr"],
                  returns: "ptr",
              },
              SendMessageW: {
                  args: ["ptr", "u32", "u64", "ptr"],
                  returns: "i64",
              },
              BringWindowToTop: {
                  args: ["ptr"],
                  returns: "bool",
              },
          })
        : null;

const ensureWindows = () => {
    if (process.platform !== "win32" || user32 === null) {
        throw new Error("WeChat host bridge is only supported on Windows.");
    }
    if (process.arch !== "x64") {
        throw new Error("WeChat host bridge only supports amd64 Windows.");
    }
};

const encodeWideString = (value: string) => Buffer.from(`${value}\0`, "utf16le");

const writePointer = (view: DataView, offset: number, value: number) => {
    view.setBigUint64(offset, BigInt(value), true);
};

const findWindowByClassName = (className: string) =>
    user32.symbols.FindWindowW(encodeWideString(className), null);

const getWeChatWindow = (): WeChatWindowHandle => {
    ensureWindows();

    const mainHandle = findWindowByClassName(MAIN_WINDOW_CLASS);
    if (mainHandle !== null) {
        return {
            window: "main",
            handle: mainHandle,
        };
    }

    const loginHandle = findWindowByClassName(LOGIN_WINDOW_CLASS);
    if (loginHandle !== null) {
        return {
            window: "login",
            handle: loginHandle,
        };
    }

    return {
        window: "none",
        handle: null,
    };
};

const encodeMiniAppLaunchPayload = (appid: string) =>
    Buffer.from(
        JSON.stringify({
            appid,
            op_type: "desktop_launch_wechat_app",
        }),
        "utf8",
    );

const buildCopyData = (handle: number, payloadBytes: Buffer) => {
    const structBuffer = new ArrayBuffer(COPYDATASTRUCT_SIZE);
    const view = new DataView(structBuffer);
    writePointer(view, 0, handle);
    view.setUint32(CBDATA_OFFSET, payloadBytes.byteLength, true);
    writePointer(view, LPDATA_OFFSET, ptr(payloadBytes));
    return new Uint8Array(structBuffer);
};

const runBridge = async (
    operation: "status" | "spawn",
    appid?: string,
): Promise<WeChatStatus> => {
    const status = getWeChatWindow();

    if (operation === "status") {
        return { window: status.window };
    }

    if (status.window === "none" || status.handle === null) {
        throw new Error("WeChat window not found");
    }

    const normalizedAppId = appid?.trim() ?? "";
    if (!normalizedAppId) {
        throw new Error("appid is required");
    }

    const payloadBytes = encodeMiniAppLaunchPayload(normalizedAppId);
    const copyData = buildCopyData(status.handle, payloadBytes);

    user32.symbols.SendMessageW(
        status.handle,
        WM_COPYDATA,
        BigInt(MINIAPP_LAUNCH_WPARAM),
        copyData,
    );
    user32.symbols.BringWindowToTop(status.handle);

    return { window: status.window };
};

const get_wechat_status = () => runBridge("status");

const spawn_miniapp = (appid: string) => runBridge("spawn", appid);

export { get_wechat_status, spawn_miniapp, WeChatStatus, WeChatWindow };
