FROM node:18

WORKDIR /practice-security/kv

COPY [ "app.js", "package.json", "./" ]
COPY [ "app.js", "package-lock.json", "./" ]

RUN npm i

ENTRYPOINT ["node", "app.js"]