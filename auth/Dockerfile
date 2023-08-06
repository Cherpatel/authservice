FROM node:18

WORKDIR /practice-security/auth

COPY [ "app.js", "package.json", "./" ]
COPY [ "app.js", "package-lock.json", "./" ]

RUN npm i

ENTRYPOINT ["node", "app.js"]