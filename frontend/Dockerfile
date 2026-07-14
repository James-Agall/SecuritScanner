# syntax=docker/dockerfile:1

# Dev-server image: this project is a local dev tool (see CLAUDE.md), so
# there's no separate "build" stage here - just install deps and run Vite's
# dev server directly, matching how target/scanner already run interpreted
# source rather than building artifacts.
FROM node:22-slim
WORKDIR /app

# Layer-caching optimization: reinstall deps only when the lockfile changes,
# not on every source edit.
COPY package.json package-lock.json ./
RUN npm ci

COPY . .

EXPOSE 5173

# --host 0.0.0.0 is mandatory: Vite's dev server binds 127.0.0.1 by default,
# which inside a container means unreachable from the host (the same class
# of bug as local_target.py's Flask app defaulting to loopback-only).
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0"]
