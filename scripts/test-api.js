#!/usr/bin/env node

const DEFAULT_BASE_URL = "http://127.0.0.1:62000";

const printUsage = () => {
    console.log(`Usage:
  node scripts/test-api.js status [--base-url <url>]
  node scripts/test-api.js list [--base-url <url>]
  node scripts/test-api.js spawn <appid> [--base-url <url>]
  node scripts/test-api.js despawn <appid> [--base-url <url>]
  node scripts/test-api.js sqlcipher-list [--base-url <url>]
  node scripts/test-api.js sqlcipher-query <database> <sql> [--base-url <url>] [--params <json>] [--max-rows <n>]
  node scripts/test-api.js sqlcipher-smoke <database> [--base-url <url>]
  node scripts/test-api.js full-test <appid> [--base-url <url>] [--wait-ms <ms>]
`);
};

const parseArgs = (argv) => {
    const args = argv.slice(2);
    if (args.length === 0 || args.includes("-h") || args.includes("--help")) {
        return { command: "help", baseUrl: DEFAULT_BASE_URL, positional: [] };
    }

    const command = args[0];
    const positional = [];
    let baseUrl = DEFAULT_BASE_URL;
    let waitMs = 4000;
    let params = [];
    let maxRows = undefined;

    for (let i = 1; i < args.length; i += 1) {
        const value = args[i];
        if (value === "--base-url") {
            i += 1;
            baseUrl = args[i] || DEFAULT_BASE_URL;
            continue;
        }
        if (value === "--wait-ms") {
            i += 1;
            waitMs = Number(args[i] || waitMs);
            continue;
        }
        if (value === "--params") {
            i += 1;
            params = JSON.parse(args[i] || "[]");
            continue;
        }
        if (value === "--max-rows") {
            i += 1;
            maxRows = Number(args[i] || "0");
            continue;
        }
        positional.push(value);
    }

    return { command, baseUrl, waitMs, params, maxRows, positional };
};

const request = async (baseUrl, pathname, init) => {
    const response = await fetch(`${baseUrl}${pathname}`, init);
    const text = await response.text();
    let data = null;
    try {
        data = text.length > 0 ? JSON.parse(text) : null;
    } catch (error) {
        data = text;
    }

    return {
        status: response.status,
        ok: response.ok,
        data,
    };
};

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const printResult = (label, result) => {
    console.log(`== ${label} ==`);
    console.log(`status: ${result.status}`);
    console.log(JSON.stringify(result.data, null, 2));
};

const getStatus = async (baseUrl) => {
    return request(baseUrl, "/api/wechat/status", {
        method: "GET",
    });
};

const listMiniapps = async (baseUrl) => {
    return request(baseUrl, "/api/miniapps", {
        method: "GET",
    });
};

const spawnMiniapp = async (baseUrl, appid) => {
    return request(baseUrl, "/api/miniapps", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
        },
        body: JSON.stringify({ appid }),
    });
};

const despawnMiniapp = async (baseUrl, appid) => {
    return request(baseUrl, `/api/miniapps/${encodeURIComponent(appid)}`, {
        method: "DELETE",
    });
};

const listSqlcipherDatabases = async (baseUrl) => {
    return request(baseUrl, "/api/sqlcipher/databases", {
        method: "GET",
    });
};

const querySqlcipher = async (baseUrl, database, sql, params, maxRows) => {
    const body = { database, sql, params };
    if (maxRows !== undefined) {
        body.maxRows = maxRows;
    }
    return request(baseUrl, "/api/sqlcipher/query", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
        },
        body: JSON.stringify(body),
    });
};

const smokeSqlcipher = async (baseUrl, database) => {
    const listResult = await listSqlcipherDatabases(baseUrl);
    printResult("sqlcipher databases", listResult);
    if (!listResult.ok) {
        process.exitCode = 1;
        return;
    }

    const countResult = await querySqlcipher(
        baseUrl,
        database,
        "SELECT count(*) FROM sqlite_master",
        [],
    );
    printResult("sqlcipher sqlite_master count", countResult);
    if (!countResult.ok) {
        process.exitCode = 1;
        return;
    }

    const schemaResult = await querySqlcipher(
        baseUrl,
        database,
        "SELECT name, type FROM sqlite_master ORDER BY name LIMIT 5",
        [],
    );
    printResult("sqlcipher schema sample", schemaResult);
    if (!schemaResult.ok) {
        process.exitCode = 1;
    }
};

const runFull = async (baseUrl, appid, waitMs) => {
    const statusBefore = await getStatus(baseUrl);
    printResult("wechat status", statusBefore);

    const listBefore = await listMiniapps(baseUrl);
    printResult("miniapps before", listBefore);

    const spawnResult = await spawnMiniapp(baseUrl, appid);
    printResult("spawn", spawnResult);
    if (!spawnResult.ok || !spawnResult.data || !spawnResult.data.miniappId) {
        process.exitCode = 1;
        return;
    }

    console.log(`waiting ${waitMs}ms for session bootstrap...`);
    await sleep(waitMs);

    const listAfterSpawn = await listMiniapps(baseUrl);
    printResult("miniapps after spawn", listAfterSpawn);

    const appidForSession = spawnResult.data.miniappId;
    const despawnResult = await despawnMiniapp(baseUrl, appidForSession);
    printResult("despawn", despawnResult);

    console.log(`waiting ${waitMs}ms for close...`);
    await sleep(waitMs);

    const listAfterDespawn = await listMiniapps(baseUrl);
    printResult("miniapps after despawn", listAfterDespawn);

    if (!despawnResult.ok) {
        process.exitCode = 1;
    }
};

const main = async () => {
    const { command, baseUrl, waitMs, params, maxRows, positional } = parseArgs(process.argv);

    if (command === "help") {
        printUsage();
        return;
    }

    if (command === "status") {
        printResult("wechat status", await getStatus(baseUrl));
        return;
    }

    if (command === "list") {
        printResult("miniapps", await listMiniapps(baseUrl));
        return;
    }

    if (command === "spawn") {
        const appid = positional[0];
        if (!appid) {
            printUsage();
            process.exitCode = 1;
            return;
        }
        printResult("spawn", await spawnMiniapp(baseUrl, appid));
        return;
    }

    if (command === "despawn") {
        const appid = positional[0];
        if (!appid) {
            printUsage();
            process.exitCode = 1;
            return;
        }
        printResult("despawn", await despawnMiniapp(baseUrl, appid));
        return;
    }

    if (command === "sqlcipher-list") {
        printResult(
            "sqlcipher databases",
            await listSqlcipherDatabases(baseUrl),
        );
        return;
    }

    if (command === "sqlcipher-query") {
        const database = positional[0];
        const sql = positional[1];
        if (!database || !sql) {
            printUsage();
            process.exitCode = 1;
            return;
        }
        printResult(
            "sqlcipher query",
            await querySqlcipher(baseUrl, database, sql, params, maxRows),
        );
        return;
    }

    if (command === "sqlcipher-smoke") {
        const database = positional[0];
        if (!database) {
            printUsage();
            process.exitCode = 1;
            return;
        }
        await smokeSqlcipher(baseUrl, database);
        return;
    }

    if (command === "full-test") {
        const appid = positional[0];
        if (!appid) {
            printUsage();
            process.exitCode = 1;
            return;
        }
        await runFull(baseUrl, appid, waitMs);
        return;
    }

    printUsage();
    process.exitCode = 1;
};

void main();
