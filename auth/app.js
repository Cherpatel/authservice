import Express from "express";
import cookieParser from "cookie-parser";

import jwt from "jsonwebtoken"
import md5 from "md5";
import fs from "node:fs"

const app = Express();

const availableArgs = ["--private", "--public", "--port"]
const args = process.argv;
const flags = {
    private: "",
    public: "",
    port: 8091
};

for (let i = 0; i < args.length; i++) {
    if (availableArgs.includes(args[i]))
        flags[args[i].slice(2)] = args[++i];
}

const cookieName = "jwt";
const privateKey = fs.readFileSync(flags.private);
const publicKey = fs.readFileSync(flags.public);

const db = {
    users: {}
};

app.use(cookieParser());
app.use(Express.json({
    type(req) {
      return true;
    }
}));

const checkUserCookie = (req, res, next) => {
    if (req.cookies[cookieName] === undefined)
        return res.status(401).end();
    
    const cookieValue = req.cookies[cookieName];
    
    jwt.verify(cookieValue, publicKey, (err, decode) => {
        if (err || !decode.username || !decode.password || !(decode.username in db.users)) {
            res.cookie(cookieName, '', { maxAge: -1 });
            return res.status(400).end();
        }

        req.profile = decode;
        next();
    });
}

app.post("/signup", async (req, res) => {
    const {
        username,
        password
    } = req.body;

    if (!username || !password)
        return res.status(400).end();

    if (db.users[username])
        return res.status(403).end();
    
    const hashPassword = md5(md5(password) + username);
    db.users[username] = hashPassword;
    
    const jwtToken = jwt.sign({ username, password: hashPassword }, privateKey, { algorithm: "RS256" });
    res.cookie(cookieName, jwtToken);
    res.status(200).end();
});

app.post("/login", (req, res) => {
    const {
        username,
        password
    } = req.body;

    if (username === undefined || password === undefined)
        return res.status(400).end();
    
    if (db.users[username] !== md5(md5(password) + username))
        return res.status(403).end();

    const jwtToken = jwt.sign({ username }, privateKey, { algorithm: "RS256" })
    res.cookie(cookieName, jwtToken);
    res.status(200).end();
});

app.get("/whoami", checkUserCookie, (req, res) => {
    res.send(`Hello, ${req.profile.username}`);
});

app.listen(flags.port, () => {
    console.log(`Service start ${flags.port} port`);
    console.log(`Private key path ${flags.private}`);
    console.log(`Public key path ${flags.public}`);
});