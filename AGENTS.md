# OwlRora repository guide

OwlRora is a single Rust web server with an embedded React frontend.

## Source map

- `crates/owlrora-server/src/` — Axum server and embedded frontend delivery
- `crates/owlrora-server/web/dist/` — tracked production frontend assets packaged with the server crate
- `apps/web/` — React and Vite frontend source
- `docs/` — VitePress documentation deployed with Cloudflare Workers
- `scripts/docker/` — container smoke tests
- `scripts/release/` — release version preparation and crates.io publication

## Repository boundaries

- Keep the repository free of product and domain definitions until they are explicitly designed.
- Keep frontend source in `apps/web`; do not move application source into the Rust crate.
- Keep repository documentation in `docs`; docs are not an application under `apps`.
- Keep `owlrora-server` self-contained: published crate contents must build without Node.js or files outside the crate package.
- Keep the runtime image non-root and preserve the `/health` endpoint for container health checks.

## Embedded frontend assets

- Vite builds `apps/web` into `crates/owlrora-server/web/dist`.
- The generated production assets are committed because `owlrora-server` embeds them and publishes them to crates.io.
- Run `pnpm build` after every frontend change and commit the resulting asset updates.
- Never edit generated assets directly. CI rebuilds them and rejects drift.
- Build the frontend before compiling the server when generated assets are not already present.

## Documentation

- Use VitePress under `docs` and deploy its static output with Cloudflare Workers.
- Keep docs limited to implemented behavior; do not present planned capabilities as available.
- Run `make docs-build` before submitting documentation changes.
- The `Docs` workflow always builds and dry-runs deployment. It deploys `main` only when the `docs` environment provides `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID`.

## Validation

- Run `make check`, `make test`, `make build`, `make package-check`, and `make docs-build` before submitting changes.
- Keep Cargo and pnpm lockfiles current and use locked installs and builds in CI.
- Preserve the server image smoke test whenever container startup, routing, assets, or health behavior changes.

## Server releases

- Keep the committed `owlrora-server` version at the reserved `0.0.0-dev` development sentinel.
- Release tags use `server-v<semver>`, for example `server-v0.1.0`.
- Do not commit a release-only version bump. `scripts/release/prepare_release.py` materializes the tag version in `Cargo.toml` and `Cargo.lock` inside the release workflow.
- Do not run `cargo publish` manually. The `Release Server` workflow only prepares and publishes the crate.
- Do not add main-branch comparisons, commit-history checks, or ordinary CI execution to the release workflow.
- Configure `CARGO_REGISTRY_TOKEN` as a GitHub Actions secret before creating the first release tag.
- A rerun may publish only when the existing crates.io package checksum exactly matches the package generated from the tagged source.
