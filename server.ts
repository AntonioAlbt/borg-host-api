import type { AuthenticatorTransportFuture, CredentialDeviceType } from "@simplewebauthn/types";
import { $, revision } from "bun";
import { Database } from "bun:sqlite";
import { mkdir, lstat, readdir, readlink } from "node:fs/promises";
import { getAuthenticationOptions, getRegistrationOptions, verifyAuthenticationRes, verifyRegistrationRes } from "./webauthn";
import { generate2FACode } from "./totp";

const db = new Database("auth.db");

const userCreationSQL = "CREATE TABLE IF NOT EXISTS `users` ( \
    `uid` INTEGER PRIMARY KEY NOT NULL, \
    `login` TEXT NOT NULL, \
    `pw_sha512` TEXT NOT NULL, \
    `current_challenge` TEXT NOT NULL \
);"
export interface User {
    uid: number,
    login: string,
    pw_sha512: string,
    current_challenge: string,
}
const tokenCreationSQL = "CREATE TABLE IF NOT EXISTS `tokens` ( \
    `owner` INTEGER UNSIGNED NOT NULL, \
    `token` TEXT NOT NULL, \
    `app` TEXT NOT NULL, \
    `time` TIMESTAMP NOT NULL \
);"
interface Token {
    owner: number;
    token: string;
    app: string;
    time: number;
}
const webAuthnCreationSQL = "CREATE TABLE IF NOT EXISTS `webauthn` ( \
    `name` TEXT NOT NULL, \
    `credentialID` TEXT PRIMARY KEY NOT NULL, \
    `credentialPublicKey` BLOB NOT NULL, \
    `counter` INTEGER NOT NULL, \
    `credentialDeviceType` TEXT NOT NULL, \
    `credentialBackedUp` INTEGER NOT NULL, \
    `transports` TEXT NOT NULL, \
    `uid` INTEGER NOT NULL \
);"
export interface WebAuthnData {
    name: string;
    // SQL: Encode to base64url then store as `TEXT`. Index this column
    credentialID: Uint8Array;
    // SQL: Store raw bytes as `BYTEA`/`BLOB`/etc...
    credentialPublicKey: Uint8Array;
    // SQL: Consider `BIGINT` since some authenticators return atomic timestamps as counters
    counter: number;
    // SQL: `VARCHAR(32)` or similar, longest possible value is currently 12 characters
    // Ex: 'singleDevice' | 'multiDevice'
    credentialDeviceType: CredentialDeviceType;
    // SQL: `BOOL` or whatever similar type is supported
    credentialBackedUp: boolean;
    // SQL: `VARCHAR(255)` and store string array as a CSV string
    // Ex: ['ble' | 'cable' | 'hybrid' | 'internal' | 'nfc' | 'smart-card' | 'usb']
    transports: AuthenticatorTransportFuture[];
    uid: number;
};
export type WebAuthnDataRaw = Omit<WebAuthnData, "credentialID" | "transports" | "credentialBackedUp"> & {
    credentialID: string;
    transports: string;
    credentialBackedUp: number;
}
db.run(userCreationSQL)
db.run(tokenCreationSQL)
db.run(webAuthnCreationSQL)

const tempMountData = new Map<string, any>();
const mountTimeoutTasks = new Map<string, ReturnType<typeof setTimeoutWithTimeLeft>>();
const lastMountAccess = new Map<string, Date>();

const currentTempAuthSessions = new Array<{ tempToken: string, appName: string, login: string, uid: number }>();

function generateCode(length = 64): string {
    const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let code = "";
    for (let i = 0; i < length; i++) {
        const randomIndex = Math.floor(Math.random() * characters.length);
        code += characters.charAt(randomIndex);
    }
    return code;
}

function getTokenFromRequest(req: Request) {
    const auth = req.headers.get("Authorization")
    if (!auth) return null;
    const token = auth.split(" ")[1];
    if (!token) return null;
    return token;
}

function authenticate(req: Request) {
    const token = getTokenFromRequest(req);
    if (!token) return false;
    const res = db.query("SELECT * FROM tokens WHERE token = ?;").get(token) as Token | null;
    return res;
}

function checkToken(token: string) {
    const res = db.query("SELECT * FROM tokens WHERE token = ?;").get(token) as Token | null;
    return res;
}

function checkLogin(login: string, pwHash: string) {
    const res = db.query("SELECT uid FROM users WHERE login = ? AND pw_sha512 = ?;").get(login, pwHash) as { uid: number } | null;
    if (!res) return false;
    else return res.uid;
}

function createNewToken(owner: number, app: string, time: number) {
    const token = generateCode(128);
    db.query("INSERT INTO tokens VALUES(?, ?, ?, ?);").run(owner, token, app, time);
    return token;
}

function getUserFromId(uid: number) {
    return db.query("SELECT * FROM users WHERE uid = ?;").get(uid) as User | null;
}

function deleteToken(token: string) {
    db.query("DELETE FROM tokens WHERE token = ?;").run(token);
}

export function setUserCurrentChallenge(uid: number, challenge: string) {
    db.query("UPDATE users SET current_challenge = ? WHERE uid = ?;").run(challenge, uid);
}

export function getUserAuthenticators(uid: number) {
    return (db.query("SELECT * FROM webauthn WHERE uid = ?;").all(uid) as WebAuthnDataRaw[]).map((d) => ({...d, credentialID: new Uint8Array(Buffer.from(d.credentialID, "base64url").buffer), transports: d.transports.split(","), credentialBackedUp: d.credentialBackedUp == 1})) as WebAuthnData[];
}

export function getUserCurrentChallenge(uid: number) {
    return getUserFromId(uid)?.current_challenge
}

export function addNewAuthenticator(data: WebAuthnData) {
    db.query("INSERT INTO webauthn VALUES(?, ?, ?, ?, ?, ?, ?, ?);").run(data.name, Buffer.from(data.credentialID).toString("base64url"), data.credentialPublicKey, data.counter, data.credentialDeviceType, data.credentialBackedUp, data.transports?.join(",") ?? "", data.uid);
}

function getAllUsers() {
    return db.query("SELECT * FROM users;").all() as User[];
}

function addNewUser(user: User) {
    db.query("INSERT INTO users VALUES(?, ?, ?, ?);").run(user.uid, user.login, user.pw_sha512, user.current_challenge);
}

function formatPasskeyId(id: Uint8Array | string) {
    if (typeof id == "string") return id;
    else return Buffer.from(id).toString("base64url");
}

function removePasskey(id: Uint8Array | string) {
    db.query("DELETE FROM webauthn WHERE credentialID = ?;").run(formatPasskeyId(id));
}

export function getPasskeyFromIDAndUser(uid: number, id: Uint8Array | string) {
    return db.query("SELECT * FROM webauthn WHERE uid = ? AND credentialID = ?;").get(uid, formatPasskeyId(id)) as WebAuthnData | null;
}

export function updatePasskeyCounter(id: Uint8Array | string, newCounter: number) {
    db.query("UPDATE webauthn SET counter = ? WHERE credentialID = ?;").run(newCounter, formatPasskeyId(id))
}

async function createMountPath(uid: number) {
    const path = "/tmp/borghostapi_" + generateCode(16) + "_" + uid + "_" + Date.now();
    await mkdir(path, { recursive: true });
    return path;
}

async function getActiveBorgMounts() {
    const mountOut = await $`mount`.text();
    const mlines = mountOut.split("\n").filter((l) => l.includes(" on "));
    const split1 = mlines.map((l) => l.split(" on "));
    const split2 = split1.map((s) => s[1].split(" type "));
    const split3 = split2.map((s) => s[1].split(" (").map((s) => { if (s.endsWith(")")) return s.substring(0, s.length - 2); else return s }));
    const split4 = split3.map((s) => s[1].split(",").map((s) => s.trim()));
    const mounts = split1.map((s, i) => ({ type: s[0], path: split2[i][0], options: split4[i] }));
    // console.log(mounts.map((o) => o.options))
    // console.log(mounts)
    const borgs = mounts.filter((m) => m.type == "borgfs");
    return borgs.map((v) => trimPrefix(v.path));
}

async function getActiveBorgMountsForUid(uid: number) {
    return (await getActiveBorgMounts()).filter((m) => {
        const parts = m.split("_")
        return parts[parts.length - 2] == `${uid}`;
    })
}

async function doUmount(path: string) {
    const success = (await $`umount ${pathPrefix + path}`).exitCode == 0;
    try {
        await $`rmdir ${pathPrefix + path}`;
    } catch { }
    if (success) {
        const p = trimPrefix(path);
        tempMountData.delete(p);
        mountTimeoutTasks.delete(p);
        lastMountAccess.delete(p);
        server.publish("mounts-" + path.split("_")[1], JSON.stringify({ event: "umount", path: path, success }));
    }
    return success;
}

async function getReqData(req: Request): Promise<any> {
    try {
        return await req.json()
    } catch (e) {
        console.error(e)
        return null;
    }
}

async function readAllKnownIdMappings(): Promise<{ [key: string]: any }> {
    const cache = Bun.file("id-repo-cache.json");
    if (!await cache.exists()) await Bun.write("id-repo-cache.json", "{}");
    return cache.json();
}
async function setIdMapping(theId: string, repo?: string) {
    await Bun.write("id-repo-cache.json", JSON.stringify({ ...(await readAllKnownIdMappings()), [theId]: repo }));
}

function json(object: any, status: number = 200) {
    return Response.json(object, { status, headers: { "Access-Control-Allow-Origin": "*", "Access-Control-Max-Age": (1 * 24 * 60 * 60).toString() } });
}

function setTimeoutWithTimeLeft(callback: Bun.TimerHandler, delay: number) {
    let start = Date.now();
    let timerId = setTimeout(callback, delay);

    return {
        timerId: timerId,
        timeLeft: function () {
            return delay - (Date.now() - start);
        }
    };
}

const pathPrefix = "/tmp/borghostapi_";
function trimPrefix(input: string) {
    if (input.startsWith(pathPrefix)) return input.substring(pathPrefix.length);
    else return input;
}

const umountTimeout = 5 * 60 * 1000;
function refreshTimeout(path: string) {
    const p = trimPrefix(path);
    if (mountTimeoutTasks.has(p)) {
        clearTimeout(mountTimeoutTasks.get(p)?.timerId);
        mountTimeoutTasks.delete(p);
    }
    mountTimeoutTasks.set(p, setTimeoutWithTimeLeft(() => doUmount(path), umountTimeout));
    lastMountAccess.set(p, new Date());
}


// --- check and umount too old borg mounts ---
// console.log(await getActiveBorgMounts());
const idRepoMap = await readAllKnownIdMappings();
const usedIds: string[] = [];
(await getActiveBorgMounts()).map((dirname) => {
    const splits = dirname.split("_");
    const time = Number.parseInt(splits[splits.length - 1]);
    const p = trimPrefix(dirname);
    if (time > Date.now() + umountTimeout) {
        doUmount(p);
        console.log("found old repo", pathPrefix + dirname, "-> unmounted");
    } else {
        mountTimeoutTasks.set(p, setTimeoutWithTimeLeft(() => doUmount(p), umountTimeout));
        lastMountAccess.set(p, new Date(time));
        tempMountData.set(p, idRepoMap[p]);
        console.log("found old repo", pathPrefix + dirname, "-> loaded back");
        usedIds.push(p);
    }
});
Object.entries(idRepoMap).forEach((val) => { if (!usedIds.includes(val[0])) setIdMapping(val[0], undefined) });

// --- start server ---
const server = Bun.serve({
    async fetch(req) {
        if (req.method == "OPTIONS") {
            return new Response("", { headers: { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "*", "Access-Control-Allow-Headers": "*", "Access-Control-Max-Age": (1 * 24 * 60 * 60).toString() } })
        }
        const url = new URL(req.url);
        if (url.pathname == "/auth/login") {
            const data = await getReqData(req);
            if (!data.login || !data.pw || !data.appname) throw Error("data missing");
            const login = data.login;
            const pwHasher = new Bun.CryptoHasher("sha512");
            pwHasher.update(data.pw);
            const pwHash = pwHasher.digest("hex");
            const appName = data.appname;
            const timestamp = Math.floor(Date.now() / 1000);

            const uid = checkLogin(login, pwHash);
            if (uid == false) throw Error("invalid auth");
            if (getUserAuthenticators(uid).length > 0) {
                const tempToken = generateCode(32);
                currentTempAuthSessions.push({ tempToken, appName, login, uid });
                return json({ "2fa": true, tempToken });
            } else {
                const token = createNewToken(uid, appName, timestamp);
                return json({ token, timestamp, "2fa": false });
            }
        } else if (url.pathname.startsWith("/viewer/")) {
            return new Response(Bun.file("viewer/" + url.pathname.substring("/viewer/".length)));
        } else if (url.pathname == "/" || url.pathname == "") {
            return Response.redirect("/viewer/index.html", 301);
        } else if (url.pathname.startsWith("/watch/mounts/")) {
            const token = url.pathname.substring("/watch/mounts/".length)
            const check = checkToken(token)
            if (!check) return json({ error: "no auth" }, 401);

            if (server.upgrade(req, { data: { opener: "mount", token: check.token, uid: check.owner } })) return json({ success: true });
            return json({ error: "failed to upgrade to websocket" });
        } else if (url.pathname == "/test/auth/register-test-user") {
            const testData = await Bun.file("test-user.json").json();
            const users = getAllUsers();
            if (users.some((u) => u.login == testData.login)) throw Error("hmm");

            const uid = users.length > 0 ? Math.max(...users.map((u) => u.uid)) + 1 : 1;
            const pw_sha512 = new Bun.CryptoHasher("sha512").update(testData.password).digest("hex");
            addNewUser({
                uid,
                login: testData.login,
                pw_sha512,
                current_challenge: "",
            });

            return json({ success: true, uid });
        } else if (url.pathname.startsWith("/auth/login/2fa")) {
            const tempToken = getTokenFromRequest(req);
            const tempTokenDataIndex = currentTempAuthSessions.findIndex((s) => s.tempToken == tempToken);
            if (tempTokenDataIndex < 0) return json({error: "invalid auth"}, 401);
            const tempTokenData = currentTempAuthSessions[tempTokenDataIndex];

            if (url.pathname == "/auth/login/2fa/code") {
                const data = await getReqData(req);
                const auths = getUserAuthenticators(tempTokenData.uid);
                if (auths.length < 1) throw Error("invalid");
                if (data.code.toString() == generate2FACode(auths[0]).otp.toString()) {
                    const timestamp = Math.floor(Date.now() / 1000);
                    const token = createNewToken(tempTokenData.uid, tempTokenData.appName, timestamp);
                    return json({ success: true, token, timestamp });
                } else throw Error("invalid code");
            } else if (url.pathname == "/auth/login/2fa/webauthn/options") {
                return json(await getAuthenticationOptions(tempTokenData.uid));
            } else if (url.pathname == "/auth/login/2fa/webauthn/handle") {
                const data = await getReqData(req);
                const res = await verifyAuthenticationRes(data, tempTokenData.uid);
                if (res.verified) {
                    const timestamp = Math.floor(Date.now() / 1000);
                    const token = createNewToken(tempTokenData.uid, tempTokenData.appName, timestamp);
                    return json({ success: true, token, timestamp });
                } else throw Error("invalid auth");
            }
        }

        const auth = authenticate(req);
        if (!auth) return json({error: "no auth"}, 401);

        if (url.pathname == "/webauthn/registration/options") {
            return json(await getRegistrationOptions(getUserFromId(auth.owner)!));
        } else if (url.pathname == "/webauthn/registration/handle") {
            return json(await verifyRegistrationRes(await getReqData(req), auth.owner));
        } else if (url.pathname == "/get/passkeys") {
            return json({ passkeys: getUserAuthenticators(auth.owner).map((data) => ({ ...data, credentialID: Buffer.from(data.credentialID).toString("base64url") })) });
        }

        const passkeys = getUserAuthenticators(auth.owner);

        if (url.pathname == "/auth/check") {
            return json({ ...auth, owner: { ...(getUserFromId(auth.owner) as any), pw_sha512: undefined, secure: passkeys.length > 0 } });
        }

        if (passkeys.length == 0) return json({ error: "requested secure method, but user has no 2fa" }, 401);

        if (url.pathname == "/webauthn/2fa-code") {
            return json({ code: generate2FACode(passkeys[0]) });
        } else if (url.pathname.startsWith("/remove/passkey/")) {
            const id = url.pathname.split("/")[3];
            if (getUserAuthenticators(auth.owner).some((cred) => Buffer.from(cred.credentialID).toString("base64url") == id)) {
                removePasskey(id);
                return json({ success: true });
            } else throw Error("no matching passkey found");
        }

        if (url.pathname == "/auth/remove-token") {
            deleteToken(auth.token);
            return json({success: true});
        } else if (url.pathname == "/get/admin/all-mounts") {
            return json({ mounts: (await getActiveBorgMounts()).map((p) => ({ path: p, repo: tempMountData.get(p) ?? null, access_ms: lastMountAccess.get(p)?.getTime() ?? null, umount_in_ms: mountTimeoutTasks.get(p)?.timeLeft() })) });
        } else if (url.pathname == "/get/mounts") {
            return json({ uid: auth.owner, mounts: (await getActiveBorgMountsForUid(auth.owner)).map((p) => ({ path: p, repo: tempMountData.get(p) ?? null, access_ms: lastMountAccess.get(p)?.getTime() ?? null, umount_in_ms: mountTimeoutTasks.get(p)?.timeLeft() })) });
        } else if (url.pathname == "/do/mount") {
            const data = await getReqData(req);
            if (!data.repo || !data.passphrase) throw Error("invalid repo data");
            const repoUrl = new URL(data.repo);
            if (repoUrl.protocol != "ssh:" && repoUrl.protocol != "file:") throw Error("invalid repo url");
            const path = await createMountPath(auth.owner);
            const borgshell = $`/usr/bin/borg --log-json mount ${data.repo} ${path}`.env({ BORG_PASSPHRASE: data.passphrase })//.quiet();
            const borgshellOut = await borgshell;
            const out = borgshellOut.text();
            const rc = borgshellOut.exitCode;
            if (rc != 0) {
                return json({
                    error: borgshellOut.stderr.toString().split("\n")
                        .filter((m) => m.startsWith("{")).map((l) => JSON.parse(l).msgid)[0],
                });
            } else {
                const accessTime = new Date();
                server.publish("mounts-" + auth.owner, JSON.stringify({ event: "mount", repo: data.repo, path: trimPrefix(path), access_ms: accessTime.getTime(), umount_in_ms: umountTimeout }));

                tempMountData.set(trimPrefix(path), data.repo);
                mountTimeoutTasks.set(trimPrefix(path), setTimeoutWithTimeLeft(() => doUmount(path), umountTimeout));
                lastMountAccess.set(trimPrefix(path), accessTime);
                setImmediate(() => setIdMapping(trimPrefix(path), data.repo));
                return json({ success: true, path: trimPrefix(path) });
            }
        } else if (url.pathname == "/do/umount") {
            const data = await getReqData(req);
            if (!data.path) throw Error("path missing");
            if (!(await getActiveBorgMountsForUid(auth.owner)).includes(data.path)) throw Error("unknown path");
            const success = await doUmount(data.path);
            return json({ success });
        } else if (url.pathname.startsWith("/access")) {
            const repoPath = decodeURI(url.pathname).split("/").slice(2);
            if (!(await getActiveBorgMountsForUid(auth.owner)).includes(repoPath[0])) throw Error("unknown path");

            refreshTimeout(repoPath[0]);

            const path = pathPrefix + repoPath[0] + "/" + repoPath.slice(1).join("/");
            
            const finfo = await lstat(path);
            if (finfo.isSymbolicLink()) {
                const target = await readlink(path);
                return json({
                    symlink: true,
                    linking_to: trimPrefix(target),
                    accessible: target.startsWith(pathPrefix),
                });
            } else if (req.method == "OPTIONS") {
                return json({
                    filename: path.split("/")[path.split("/").length - (path.endsWith("/") ? 2 : 1)],
                    full_path: trimPrefix(path),
                    access_ms: finfo.atimeMs,
                    modified_ms: finfo.mtimeMs,
                    // mode: finfo.mode,
                    size_b: finfo.size,
                    is_file: finfo.isFile(),
                    is_dir: finfo.isDirectory(),
                    lnk: finfo.isSymbolicLink() ? await readlink(path) : null,
                });
            }
            if (finfo.isDirectory()) {
                return json(await Promise.all((await readdir(path)).map(async (fn) => {
                    const filePath = path + (path.endsWith("/") ? "" : "/") + fn;
                    const finfo = await lstat(filePath);
                    return ({
                        filename: fn,
                        full_path: trimPrefix(filePath),
                        last_access: finfo.atimeMs,
                        last_modified: finfo.mtimeMs,
                        // mode: finfo.mode,
                        size: finfo.size,
                        file: finfo.isFile(),
                        dir: finfo.isDirectory(),
                        lnk: finfo.isSymbolicLink() ? await readlink(filePath) : null,
                    });
                })));
            } else if (finfo.isFile()) {
                const mimeType = await $`/usr/bin/file --mime ${path}`.text(); // output e.g.: /tmp/.../file: application/json; encoding=utf-8
                const seemsLikeText = mimeType.includes("text/") || ["application/json", "application/ld+json", "application/x-httpd-php", "application/x-sh", "application/xhtml+xml", "application/xml"].some((mime) => mimeType.includes(mime));
                if (url.searchParams.has("text")) return json({ text_content: await Bun.file(path).text(), seems_like_text: seemsLikeText });
                if (url.searchParams.has("download")) return new Response(Bun.file(path));
                if (url.searchParams.has("gzip")) return new Response(Bun.gzipSync(await Bun.file(path).arrayBuffer()));
                return json({
                    base64_gzip_content: Buffer.from(Bun.gzipSync(await Bun.file(path).arrayBuffer())).toString("base64"),
                    seems_like_text: seemsLikeText,
                });
            }
        }

        return new Response("not found", { status: 404 });
    },
    error: (err) => {
        console.error(err)
        return json({ error: err.message }, 500);
    },
    websocket: {
        message(ws, message) {
            console.log("- message from websocket " + ws.remoteAddress + ": " + message)
        },
        open(ws) {
            const data = ws.data as { opener: string, uid: number, token: string } | undefined
            if (data && data.opener == "mount") {
                ws.subscribe("mounts-" + data.uid)
                ws.send(JSON.stringify({ event: "subscribed", to: "mounts-" + data.uid }))
            }
        },
    },

    tls: process.env.ENABLE_TLS === "true" ? {
        cert: Bun.file("tls/fullchain.pem"),
        key: Bun.file("tls/privkey.pem"),
    } : undefined,
    
    hostname: process.env.SERVER_HOSTNAME ?? "0.0.0.0",
    port: isNaN(Number.parseInt(process.env.SERVER_PORT ?? "x")) ? 3000 : Number.parseInt(process.env.SERVER_PORT!),
});

console.log("Server started on " + server.hostname + ":" + server.port)
