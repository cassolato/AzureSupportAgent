# Local development image for the Vite dev server (used by docker-compose).
# Pinned to an explicit patch release rather than the mutable `20-alpine` tag so
# rebuilds are reproducible and a compromised/updated upstream tag cannot silently
# change what runs here (CWE-494).
FROM node:20.19.5-alpine

WORKDIR /app
RUN chown node:node /app

# Drop root: the base image ships an unprivileged `node` user (uid 1000).
USER node

# `npm ci` installs exactly the audited tree from package-lock.json. `npm install`
# is free to resolve newer transitive versions at build time, which silently
# bypasses the lockfile and any `overrides` pinning applied to it.
COPY --chown=node:node package.json package-lock.json ./
RUN npm ci

COPY --chown=node:node . .

EXPOSE 5173

CMD ["npm", "run", "dev"]
