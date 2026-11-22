# The browser of "castor conformance": Chromium as the pinned image of Playwright ships it, and the client
# library of the same version, which drives no other build of the browser. capture.mjs is mounted by
# compose.yaml, not copied, so that a change to it needs no new image.
FROM mcr.microsoft.com/playwright:v1.64.1-noble

WORKDIR /browser
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund
