import { createHash, pbkdf2Sync } from "node:crypto";
import {
    closeSync,
    existsSync,
    openSync,
    readFileSync,
    readdirSync,
    readSync,
    statSync,
} from "node:fs";
import { delimiter, dirname, extname, join, relative, resolve, sep } from "node:path";

import { Logger } from "./logger";

type SqlcipherSymbols = Record<string, (...args: any[]) => any>;

type SqlcipherLibrary = {
    handle: unknown;
    symbols: SqlcipherSymbols;
    read: {
        u8: (pointer: number, byteOffset: number) => number;
    };
};

type SqlcipherCacheEntry = {
    db: number;
    path: string;
    timer: NodeJS.Timeout;
};

type SqlValue =
    | null
    | string
    | number
    | { type: "integer"; value: string }
    | { type: "blob"; base64: string };

type QueryRequest = {
    database: string;
    sql: string;
    params?: unknown[];
    maxRows?: number;
};

type QueryResult = {
    database: string;
    columns: string[];
    rows: SqlValue[][];
    rowCount: number;
    truncated: boolean;
};

class SqlcipherError extends Error {
    statusCode: number;

    constructor(statusCode: number, message: string) {
        super(message);
        this.statusCode = statusCode;
    }
}

const SQLITE_OK = 0;
const SQLITE_ROW = 100;
const SQLITE_DONE = 101;
const SQLITE_OPEN_READONLY = 0x00000001;
const SQLITE_INTEGER = 1;
const SQLITE_FLOAT = 2;
const SQLITE_TEXT = 3;
const SQLITE_BLOB = 4;
const SQLITE_NULL = 5;
const IDLE_TIMEOUT_MS = 15 * 60 * 1000;
const DEFAULT_MAX_ROWS = 1000;
const MAX_MAX_ROWS = 10000;
const KEY_HEX_PATTERN = /^[0-9a-fA-F]{64}$/;

const nativeLibraryPath = () =>
    process.env.WMPF_SQLCIPHER_LIBRARY ||
    resolve(process.cwd(), "native", "sqlcipher.dll");

const hasDirectoryPart = (path: string) => path.includes("/") || path.includes("\\");

const prependWindowsDllDirectory = (libraryPath: string) => {
    if (process.platform !== "win32" || !hasDirectoryPart(libraryPath)) {
        return;
    }

    const libraryDirectory = resolve(dirname(libraryPath));
    const pathValue = process.env.PATH || "";
    const entries = pathValue.split(delimiter).filter(Boolean);
    const alreadyPresent = entries.some(
        (entry) => resolve(entry).toLowerCase() === libraryDirectory.toLowerCase(),
    );
    if (!alreadyPresent) {
        process.env.PATH = [libraryDirectory, ...entries].join(delimiter);
    }
};

const makeCString = (value: string) => Buffer.from(`${value}\0`, "utf8");

const readPointer = (buffer: Buffer) => Number(buffer.readBigUInt64LE(0));

const pointerHash = (value: string) =>
    createHash("sha256").update(value).digest("hex").slice(0, 16);

const isPathInside = (root: string, target: string) => {
    const relativePath = relative(root, target);
    return (
        relativePath === "" ||
        (!relativePath.startsWith("..") && !relativePath.startsWith(sep))
    );
};

const stripSqlCommentsAndWhitespace = (value: string) => {
    let rest = value;
    while (rest.length > 0) {
        const trimmed = rest.trimStart();
        if (trimmed.startsWith("--")) {
            const newlineIndex = trimmed.search(/\r?\n/);
            rest = newlineIndex === -1 ? "" : trimmed.slice(newlineIndex);
            continue;
        }
        if (trimmed.startsWith("/*")) {
            const endIndex = trimmed.indexOf("*/", 2);
            if (endIndex === -1) {
                return trimmed;
            }
            rest = trimmed.slice(endIndex + 2);
            continue;
        }
        return trimmed;
    }
    return "";
};

const normalizeDatabasePath = (root: string, database: string) => {
    const databaseName = database.trim();
    if (!databaseName) {
        throw new SqlcipherError(400, "database is required");
    }
    if (
        databaseName.includes("\0") ||
        databaseName.startsWith("/") ||
        databaseName.startsWith("\\") ||
        databaseName.match(/^[a-zA-Z]:[\\/]/)
    ) {
        throw new SqlcipherError(400, "database path must be relative");
    }
    if (extname(databaseName).toLowerCase() !== ".db") {
        throw new SqlcipherError(400, "database must be a .db file");
    }

    const resolvedPath = resolve(root, databaseName);
    if (!isPathInside(root, resolvedPath)) {
        throw new SqlcipherError(400, "database path escapes configured root");
    }
    if (!existsSync(resolvedPath) || !statSync(resolvedPath).isFile()) {
        throw new SqlcipherError(404, "database not found");
    }
    return resolvedPath;
};

const readDatabaseSalt = (path: string) => {
    const salt = Buffer.alloc(16);
    const fd = openSync(path, "r");
    try {
        const bytesRead = readSync(fd, salt, 0, salt.byteLength, 0);
        if (bytesRead < salt.byteLength) {
            throw new SqlcipherError(400, "database file is too small");
        }
    } finally {
        closeSync(fd);
    }
    return salt;
};

const deriveSqlcipherKey = (path: string, baseKeyHex: string) => {
    const baseKey = Buffer.from(baseKeyHex, "hex");
    const salt = readDatabaseSalt(path);
    const derivedKey = pbkdf2Sync(baseKey, salt, 64000, 32, "sha1");
    return Buffer.concat([derivedKey, salt]).toString("hex");
};

const collectDatabases = (root: string, current = root): string[] => {
    const entries = readdirSync(current, { withFileTypes: true });
    const databases: string[] = [];
    for (const entry of entries) {
        const fullPath = join(current, entry.name);
        if (entry.isDirectory()) {
            databases.push(...collectDatabases(root, fullPath));
            continue;
        }
        if (entry.isFile() && extname(entry.name).toLowerCase() === ".db") {
            databases.push(relative(root, fullPath).split(sep).join("/"));
        }
    }
    return databases.sort();
};

class SqlcipherService {
    private library?: SqlcipherLibrary;
    private loadError?: string;
    private root?: string;
    private keyHex?: string;
    private cache = new Map<string, SqlcipherCacheEntry>();

    constructor(
        private logger: Logger,
        private configuredRoot?: string,
    ) {}

    listDatabases() {
        this.ensureConfigured(false);
        return collectDatabases(this.root!);
    }

    query(request: QueryRequest): QueryResult {
        this.ensureConfigured(true);
        const path = normalizeDatabasePath(this.root!, request.database);
        const sql = typeof request.sql === "string" ? request.sql : "";
        if (!sql.trim()) {
            throw new SqlcipherError(400, "sql is required");
        }

        const params = request.params ?? [];
        if (!Array.isArray(params)) {
            throw new SqlcipherError(400, "params must be an array");
        }

        const maxRows = this.normalizeMaxRows(request.maxRows);
        const entry = this.getCachedDatabase(path);
        try {
            return this.executeQuery(entry, request.database, sql, params, maxRows);
        } finally {
            this.scheduleClose(entry);
        }
    }

    closeAll() {
        for (const entry of this.cache.values()) {
            this.closeEntry(entry);
        }
        this.cache.clear();
    }

    private ensureConfigured(requireLibrary: boolean) {
        if (!this.root) {
            const root = this.configuredRoot || process.env.WMPF_SQLCIPHER_DB_ROOT;
            if (!root) {
                throw new SqlcipherError(503, "SQLCipher database root is not configured");
            }
            const resolvedRoot = resolve(root);
            if (!existsSync(resolvedRoot) || !statSync(resolvedRoot).isDirectory()) {
                throw new SqlcipherError(503, "SQLCipher database root is unavailable");
            }
            this.root = resolvedRoot;
        }

        if (!this.keyHex) {
            this.keyHex = this.loadKeyHex();
        }

        if (requireLibrary) {
            this.ensureLibrary();
        }
    }

    private ensureLibrary() {
        if (this.library) {
            return;
        }
        if (this.loadError) {
            throw new SqlcipherError(503, this.loadError);
        }

        const libraryPath = nativeLibraryPath();
        if (!existsSync(libraryPath) && libraryPath.includes(sep)) {
            this.loadError = "SQLCipher library is unavailable";
            throw new SqlcipherError(503, this.loadError);
        }

        try {
            prependWindowsDllDirectory(libraryPath);
            const { dlopen, FFIType, read } = require("bun:ffi");
            const library = dlopen(libraryPath, {
                sqlite3_open_v2: {
                    args: [FFIType.ptr, FFIType.ptr, FFIType.int, FFIType.ptr],
                    returns: FFIType.int,
                },
                sqlite3_close_v2: {
                    args: [FFIType.ptr],
                    returns: FFIType.int,
                },
                sqlite3_errmsg: {
                    args: [FFIType.ptr],
                    returns: FFIType.cstring,
                },
                sqlite3_exec: {
                    args: [FFIType.ptr, FFIType.ptr, FFIType.ptr, FFIType.ptr, FFIType.ptr],
                    returns: FFIType.int,
                },
                sqlite3_prepare_v2: {
                    args: [FFIType.ptr, FFIType.ptr, FFIType.int, FFIType.ptr, FFIType.ptr],
                    returns: FFIType.int,
                },
                sqlite3_bind_parameter_count: {
                    args: [FFIType.ptr],
                    returns: FFIType.int,
                },
                sqlite3_bind_null: {
                    args: [FFIType.ptr, FFIType.int],
                    returns: FFIType.int,
                },
                sqlite3_bind_int64: {
                    args: [FFIType.ptr, FFIType.int, FFIType.i64],
                    returns: FFIType.int,
                },
                sqlite3_bind_double: {
                    args: [FFIType.ptr, FFIType.int, FFIType.double],
                    returns: FFIType.int,
                },
                sqlite3_bind_text: {
                    args: [FFIType.ptr, FFIType.int, FFIType.ptr, FFIType.int, FFIType.ptr],
                    returns: FFIType.int,
                },
                sqlite3_bind_blob: {
                    args: [FFIType.ptr, FFIType.int, FFIType.ptr, FFIType.int, FFIType.ptr],
                    returns: FFIType.int,
                },
                sqlite3_step: {
                    args: [FFIType.ptr],
                    returns: FFIType.int,
                },
                sqlite3_finalize: {
                    args: [FFIType.ptr],
                    returns: FFIType.int,
                },
                sqlite3_column_count: {
                    args: [FFIType.ptr],
                    returns: FFIType.int,
                },
                sqlite3_column_name: {
                    args: [FFIType.ptr, FFIType.int],
                    returns: FFIType.cstring,
                },
                sqlite3_column_type: {
                    args: [FFIType.ptr, FFIType.int],
                    returns: FFIType.int,
                },
                sqlite3_column_int64: {
                    args: [FFIType.ptr, FFIType.int],
                    returns: FFIType.i64,
                },
                sqlite3_column_double: {
                    args: [FFIType.ptr, FFIType.int],
                    returns: FFIType.double,
                },
                sqlite3_column_text: {
                    args: [FFIType.ptr, FFIType.int],
                    returns: FFIType.ptr,
                },
                sqlite3_column_blob: {
                    args: [FFIType.ptr, FFIType.int],
                    returns: FFIType.ptr,
                },
                sqlite3_column_bytes: {
                    args: [FFIType.ptr, FFIType.int],
                    returns: FFIType.int,
                },
            });
            this.library = {
                handle: library,
                symbols: library.symbols,
                read,
            };
        } catch (error) {
            this.loadError = "failed to load SQLCipher library";
            this.logger.error("[sqlcipher] failed to load SQLCipher library:", error);
            throw new SqlcipherError(503, this.loadError);
        }
    }

    private loadKeyHex() {
        const envKey = process.env.WMPF_SQLCIPHER_KEY?.trim();
        if (envKey) {
            if (!KEY_HEX_PATTERN.test(envKey)) {
                throw new SqlcipherError(503, "WMPF_SQLCIPHER_KEY must be one 64-hex key");
            }
            return envKey;
        }

        const keyFile = process.env.WMPF_SQLCIPHER_KEY_FILE;
        if (!keyFile) {
            throw new SqlcipherError(503, "SQLCipher key is not configured");
        }

        let keyValue = "";
        try {
            keyValue = readFileSync(resolve(keyFile), "utf8").trim();
        } catch (error) {
            throw new SqlcipherError(503, "SQLCipher key file is unavailable");
        }
        if (!KEY_HEX_PATTERN.test(keyValue)) {
            throw new SqlcipherError(503, "SQLCipher key file must contain one 64-hex key");
        }
        return keyValue;
    }

    private normalizeMaxRows(value: unknown) {
        if (value === undefined) {
            return DEFAULT_MAX_ROWS;
        }
        if (
            typeof value !== "number" ||
            !Number.isInteger(value) ||
            value < 1 ||
            value > MAX_MAX_ROWS
        ) {
            throw new SqlcipherError(400, `maxRows must be between 1 and ${MAX_MAX_ROWS}`);
        }
        return value;
    }

    private getCachedDatabase(path: string) {
        const cacheKey = `${path}:${pointerHash(this.keyHex!)}`;
        const cached = this.cache.get(cacheKey);
        if (cached) {
            clearTimeout(cached.timer);
            return cached;
        }

        const entry = this.openDatabase(path);
        this.cache.set(cacheKey, entry);
        return entry;
    }

    private openDatabase(path: string): SqlcipherCacheEntry {
        const library = this.library!;
        const out = Buffer.alloc(8);
        const pathBuffer = makeCString(path);
        const rc = library.symbols.sqlite3_open_v2(
            require("bun:ffi").ptr(pathBuffer),
            require("bun:ffi").ptr(out),
            SQLITE_OPEN_READONLY,
            null,
        );
        const db = readPointer(out);
        if (rc !== SQLITE_OK || db === 0) {
            const message = db ? this.errorMessage(db) : "failed to open database";
            if (db) {
                library.symbols.sqlite3_close_v2(db);
            }
            throw new SqlcipherError(500, message);
        }

        const entry: SqlcipherCacheEntry = {
            db,
            path,
            timer: setTimeout(() => undefined, IDLE_TIMEOUT_MS),
        };
        clearTimeout(entry.timer);

        try {
            this.configureDatabase(entry);
            this.exec(entry, "SELECT count(*) FROM sqlite_master");
        } catch (error) {
            this.closeEntry(entry);
            throw error;
        }

        return entry;
    }

    private configureDatabase(entry: SqlcipherCacheEntry) {
        const sqlcipherKey = deriveSqlcipherKey(entry.path, this.keyHex!);
        this.exec(entry, `PRAGMA key = "x'${sqlcipherKey}'"`);
        this.exec(entry, "PRAGMA cipher_compatibility = 3");
        this.exec(entry, "PRAGMA cipher_page_size = 4096");
        this.exec(entry, "PRAGMA kdf_iter = 64000");
        this.exec(entry, "PRAGMA cipher_hmac_algorithm = HMAC_SHA1");
        this.exec(entry, "PRAGMA cipher_kdf_algorithm = PBKDF2_HMAC_SHA1");
    }

    private exec(entry: SqlcipherCacheEntry, sql: string) {
        const sqlBuffer = makeCString(sql);
        const rc = this.library!.symbols.sqlite3_exec(
            entry.db,
            require("bun:ffi").ptr(sqlBuffer),
            null,
            null,
            null,
        );
        if (rc !== SQLITE_OK) {
            throw new SqlcipherError(500, this.errorMessage(entry.db));
        }
    }

    private executeQuery(
        entry: SqlcipherCacheEntry,
        database: string,
        sql: string,
        params: unknown[],
        maxRows: number,
    ): QueryResult {
        const library = this.library!;
        const sqlBuffer = makeCString(sql);
        const statementOut = Buffer.alloc(8);
        const tailOut = Buffer.alloc(8);
        const sqlPointer = require("bun:ffi").ptr(sqlBuffer);
        const rc = library.symbols.sqlite3_prepare_v2(
            entry.db,
            sqlPointer,
            sqlBuffer.byteLength,
            require("bun:ffi").ptr(statementOut),
            require("bun:ffi").ptr(tailOut),
        );
        const statement = readPointer(statementOut);
        if (rc !== SQLITE_OK || statement === 0) {
            throw new SqlcipherError(400, this.errorMessage(entry.db));
        }

        let keepAlive: Buffer[] = [];
        try {
            const tailPointer = readPointer(tailOut);
            const tailOffset = Math.max(0, tailPointer - sqlPointer);
            const tail = sqlBuffer.subarray(tailOffset).toString("utf8").replace(/\0.*$/s, "");
            if (stripSqlCommentsAndWhitespace(tail).length > 0) {
                throw new SqlcipherError(400, "only one SQL statement is allowed");
            }

            keepAlive = this.bindParameters(statement, params);
            const columns = this.readColumns(statement);
            const rows: SqlValue[][] = [];
            let truncated = false;

            while (true) {
                const stepRc = library.symbols.sqlite3_step(statement);
                if (stepRc === SQLITE_ROW) {
                    if (rows.length >= maxRows) {
                        truncated = true;
                        break;
                    }
                    rows.push(this.readRow(statement, columns.length));
                    continue;
                }
                if (stepRc === SQLITE_DONE) {
                    break;
                }
                throw new SqlcipherError(400, this.errorMessage(entry.db));
            }

            return {
                database,
                columns,
                rows,
                rowCount: rows.length,
                truncated,
            };
        } finally {
            keepAlive.length = 0;
            library.symbols.sqlite3_finalize(statement);
        }
    }

    private bindParameters(statement: number, params: unknown[]) {
        const library = this.library!;
        const expectedCount = library.symbols.sqlite3_bind_parameter_count(statement);
        if (params.length !== expectedCount) {
            throw new SqlcipherError(400, `expected ${expectedCount} SQL parameter(s)`);
        }

        const keepAlive: Buffer[] = [];
        for (let index = 0; index < params.length; index += 1) {
            const value = params[index];
            const bindIndex = index + 1;
            let rc = SQLITE_OK;
            if (value === null) {
                rc = library.symbols.sqlite3_bind_null(statement, bindIndex);
            } else if (typeof value === "string") {
                const buffer = makeCString(value);
                keepAlive.push(buffer);
                rc = library.symbols.sqlite3_bind_text(
                    statement,
                    bindIndex,
                    require("bun:ffi").ptr(buffer),
                    Buffer.byteLength(value, "utf8"),
                    null,
                );
            } else if (typeof value === "number" && Number.isFinite(value)) {
                rc = Number.isInteger(value)
                    ? library.symbols.sqlite3_bind_int64(statement, bindIndex, value)
                    : library.symbols.sqlite3_bind_double(statement, bindIndex, value);
            } else if (this.isTaggedInteger(value)) {
                const bigint = BigInt(value.value);
                if (
                    bigint >= BigInt(Number.MIN_SAFE_INTEGER) &&
                    bigint <= BigInt(Number.MAX_SAFE_INTEGER)
                ) {
                    rc = library.symbols.sqlite3_bind_int64(
                        statement,
                        bindIndex,
                        Number(bigint),
                    );
                } else {
                    const buffer = makeCString(value.value);
                    keepAlive.push(buffer);
                    rc = library.symbols.sqlite3_bind_text(
                        statement,
                        bindIndex,
                        require("bun:ffi").ptr(buffer),
                        Buffer.byteLength(value.value, "utf8"),
                        null,
                    );
                }
            } else if (this.isTaggedBlob(value)) {
                const buffer = Buffer.from(value.base64, "base64");
                keepAlive.push(buffer);
                rc = library.symbols.sqlite3_bind_blob(
                    statement,
                    bindIndex,
                    require("bun:ffi").ptr(buffer),
                    buffer.byteLength,
                    null,
                );
            } else {
                throw new SqlcipherError(400, `unsupported SQL parameter at index ${index}`);
            }

            if (rc !== SQLITE_OK) {
                throw new SqlcipherError(400, "failed to bind SQL parameter");
            }
        }
        return keepAlive;
    }

    private readColumns(statement: number) {
        const library = this.library!;
        const columnCount = library.symbols.sqlite3_column_count(statement);
        const columns: string[] = [];
        for (let index = 0; index < columnCount; index += 1) {
            columns.push(String(library.symbols.sqlite3_column_name(statement, index)));
        }
        return columns;
    }

    private copyNativeBytes(pointer: number, bytes: number) {
        const buffer = Buffer.allocUnsafe(bytes);
        const read = this.library!.read;
        for (let offset = 0; offset < bytes; offset += 1) {
            buffer[offset] = read.u8(pointer, offset);
        }
        return buffer;
    }

    private readRow(statement: number, columnCount: number) {
        const row: SqlValue[] = [];
        for (let index = 0; index < columnCount; index += 1) {
            row.push(this.readValue(statement, index));
        }
        return row;
    }

    private readValue(statement: number, index: number): SqlValue {
        const library = this.library!;
        const type = library.symbols.sqlite3_column_type(statement, index);
        if (type === SQLITE_NULL) {
            return null;
        }
        if (type === SQLITE_INTEGER) {
            return {
                type: "integer",
                value: String(library.symbols.sqlite3_column_int64(statement, index)),
            };
        }
        if (type === SQLITE_FLOAT) {
            return library.symbols.sqlite3_column_double(statement, index);
        }
        if (type === SQLITE_TEXT) {
            const pointer = library.symbols.sqlite3_column_text(statement, index);
            const bytes = library.symbols.sqlite3_column_bytes(statement, index);
            if (!pointer || bytes === 0) {
                return "";
            }
            const buffer = this.copyNativeBytes(pointer, bytes);
            return buffer.toString("utf8");
        }
        if (type === SQLITE_BLOB) {
            const pointer = library.symbols.sqlite3_column_blob(statement, index);
            const bytes = library.symbols.sqlite3_column_bytes(statement, index);
            if (!pointer || bytes === 0) {
                return { type: "blob", base64: "" };
            }
            const buffer = this.copyNativeBytes(pointer, bytes);
            return {
                type: "blob",
                base64: buffer.toString("base64"),
            };
        }
        return null;
    }

    private scheduleClose(entry: SqlcipherCacheEntry) {
        entry.timer = setTimeout(() => {
            this.cache.delete(`${entry.path}:${pointerHash(this.keyHex!)}`);
            this.closeEntry(entry);
        }, IDLE_TIMEOUT_MS);
        entry.timer.unref();
    }

    private closeEntry(entry: SqlcipherCacheEntry) {
        clearTimeout(entry.timer);
        this.library?.symbols.sqlite3_close_v2(entry.db);
    }

    private errorMessage(db: number) {
        return String(this.library!.symbols.sqlite3_errmsg(db) || "SQLCipher error");
    }

    private isTaggedInteger(value: unknown): value is { type: "integer"; value: string } {
        return (
            typeof value === "object" &&
            value !== null &&
            (value as any).type === "integer" &&
            typeof (value as any).value === "string" &&
            /^-?\d+$/.test((value as any).value)
        );
    }

    private isTaggedBlob(value: unknown): value is { type: "blob"; base64: string } {
        return (
            typeof value === "object" &&
            value !== null &&
            (value as any).type === "blob" &&
            typeof (value as any).base64 === "string"
        );
    }
}

const create_sqlcipher_service = (logger: Logger, root?: string) =>
    new SqlcipherService(logger, root);

const get_sqlcipher_error_status = (error: unknown) =>
    error instanceof SqlcipherError ? error.statusCode : 500;

const get_sqlcipher_error_message = (error: unknown) =>
    error instanceof Error ? error.message : "SQLCipher error";

export {
    QueryRequest,
    QueryResult,
    SqlcipherError,
    create_sqlcipher_service,
    get_sqlcipher_error_message,
    get_sqlcipher_error_status,
};
