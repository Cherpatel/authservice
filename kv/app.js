import Express from "express";
import cookieParser from "cookie-parser";

import jwt from "jsonwebtoken"
import fs from "node:fs"

const app = Express();

const availableArgs = ["--private", "--public", "--port"]
const args = process.argv;
const flags = {
    public: "",
    port: 8091
};

for (let i = 0; i < args.length; i++) {
    if (availableArgs.includes(args[i]))
        flags[args[i].slice(2)] = args[++i];
}

const cookieName = "jwt";
const publicKey = fs.readFileSync(flags.public);

const db = {
    storage: {}
};

app.use(cookieParser());
app.use(Express.json({
    type(req) {
      return true;
    }
}));

const checkUserCookie = (req, res, next) => {
    if (!req.cookies[cookieName])
        return res.status(401).end();
    
    const cookieValue = req.cookies[cookieName];
    
    jwt.verify(cookieValue, publicKey, (err, decode) => {
        if (err || !decode.username || !decode.password) {
            res.cookie(cookieName, '', { maxAge: -1 });
            return res.status(400).end();
        }

        req.profile = decode;
        next();
    });
}

app.post("/put", checkUserCookie, (req, res) => {
    const { key } = req.query;
    const { value } = req.body;
    
    if (!key || !value)
        return res.status(400).end();

    if (db.storage[key] && db.storage[key].login !== req.profile.username)
        return res.status(403).end();
    
    db.storage[key] = { login: req.profile.username, value };
    res.status(200).end();
});

app.get('/get', checkUserCookie, (req, res) => {
    const { key } = req.query;

    if (!key)
        return res.status(400).end();
    
    if (!db.storage[key])
        return res.status(404).end();

    if (db.storage[key].login !== req.profile.username)
        return res.status(403).end();
    
    res.send({ value: db.storage[key].value });
});

app.listen(flags.port, () => {
    console.log(`Service start ${flags.port} port`);
});