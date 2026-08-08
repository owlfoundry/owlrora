FROM node:24-bookworm-slim AS web-builder

WORKDIR /workspace
RUN npm install --global pnpm@10.30.3
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY apps/web/package.json apps/web/package.json
RUN pnpm install --filter @owlrora/web... --frozen-lockfile
COPY apps/web apps/web
RUN pnpm --filter @owlrora/web build

FROM rust:bookworm AS rust-builder

WORKDIR /workspace
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates/owlrora-server/Cargo.toml crates/owlrora-server/Cargo.toml
COPY crates/owlrora-server/src crates/owlrora-server/src
COPY --from=web-builder /workspace/apps/web/dist apps/web/dist
RUN cargo build --release --locked --package owlrora-server

FROM debian:bookworm-slim AS runtime

ARG OWLRORA_VERSION=dev
ARG VCS_REF=unknown
ARG SOURCE_URL=https://github.com/owlfoundry/owlrora

LABEL org.opencontainers.image.title="OwlRora" \
      org.opencontainers.image.description="OwlRora web server" \
      org.opencontainers.image.source="${SOURCE_URL}" \
      org.opencontainers.image.version="${OWLRORA_VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.licenses="BSD-3-Clause"

RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates curl tini \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 owlrora \
    && useradd --uid 10001 --gid owlrora --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin owlrora

COPY --from=rust-builder --chown=owlrora:owlrora /workspace/target/release/owlrora-server /usr/local/bin/owlrora-server
COPY --chown=owlrora:owlrora LICENSE /usr/share/licenses/owlrora/LICENSE

USER owlrora
ENV OWLRORA_ADDR=0.0.0.0:8080
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl --fail --silent --show-error http://127.0.0.1:8080/health >/dev/null || exit 1
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/owlrora-server"]
