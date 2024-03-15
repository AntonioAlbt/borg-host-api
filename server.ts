import { Database } from "bun:sqlite";

const db = new Database("auth.db");

const userCreationSQL = "CREATE TABLE IF NOT EXISTS `users` ( \
    `uid` INTEGER PRIMARY KEY NOT NULL, \
    `login` VARCHAR(128) NOT NULL, \
    `pw_sha512` VARCHAR(128) NOT NULL \
);"
const tokenCreationSQL = "CREATE TABLE IF NOT EXISTS `tokens` ( \
    `owner` INTEGER UNSIGNED PRIMARY KEY NOT NULL, \
    `token` TEXT NOT NULL, \
    `app` VARCHAR(128) NOT NULL, \
    `time` TIMESTAMP NOT NULL \
);"
interface Token {
    owner: number;
    token: string;
    app: string;
    time: number;
}
db.run(userCreationSQL)
db.run(tokenCreationSQL)

function authenticate(req: Request) {
    const auth = req.headers.get("Authorization")
    if (!auth) return false;
    const token = auth.split(" ")[1];
    if (!token) return false;
    const res = db.query("SELECT * FROM tokens WHERE token = ?;").get(token) as Token;
    return res;
}

const server = Bun.serve({
    fetch(req) {
        const auth = authenticate(req);
        if (auth == false) return new Response("no auth\n", { status: 401, statusText: "Unauthorized" });
        return new Response(req.headers.get("Authorization"));
    },
});

console.log("Server started on " + server.hostname + ":" + server.port)
