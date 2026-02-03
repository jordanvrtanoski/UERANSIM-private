# Repository Guidelines

## Project Structure & Module Organization

- `src/`: main C/C++ sources
  - `src/gnb/`: gNB implementation
  - `src/ue/`: UE implementation
  - `src/lib/`, `src/utils/`: shared libraries/utilities
  - `src/asn/`: ASN.1 / protocol code
  - `src/ext/`: vendored third-party code
- `config/`: example YAML configs (Open5GS, free5GC, and custom)
- `tools/`: helper scripts/assets (e.g., `nr-binder`, ASN.1 specs, Wireshark dissector)
- Generated build output: `cmake-build-release/` and `build/` (do not commit)

## Build, Test, and Development Commands

- `make build`: Configure and build Release via CMake, then copy artifacts into `build/` (`nr-gnb`, `nr-ue`, `nr-cli`, `libdevbnd.so`, `nr-binder`).
- `make clean`: Remove generated build directories.
- Manual CMake:
  - `cmake -S . -B cmake-build-release -DCMAKE_BUILD_TYPE=Release`
  - `cmake --build cmake-build-release --target all`

Local run examples:

- `./build/nr-gnb -c config/open5gs-gnb.yaml`
- `./build/nr-ue -c config/open5gs-ue.yaml`
- `./build/nr-cli --dump` (list nodes), then `./build/nr-cli <node-name>`
- `./build/nr-binder <local-ip> <command...>` (bind a process using `LD_PRELOAD`), e.g. `./build/nr-binder 127.0.0.1 ./build/nr-ue -c config/custom-ue.yaml`

## Coding Style & Naming Conventions

- Language standards: C++17 and C11 (see `CMakeLists.txt`).
- Formatting: run `clang-format -i <files>`; the repo ships a `.clang-format` (Microsoft-based).
- Keep changes scoped to the relevant module directory (`src/ue/...`, `src/gnb/...`, etc.) and prefer descriptive names over abbreviations.

## Testing Guidelines

- There is no dedicated unit test suite in-tree. Treat `make build` as the minimum gate, and do a basic smoke run with sample configs plus `nr-cli` to validate behavior.

## Commit & Pull Request Guidelines

- Commit messages in history are short, imperative summaries (often with optional prefixes like `Fix:`) and may reference issues (e.g., `Fixes #766`).
- PRs should include: problem statement, approach, validation steps (exact commands/configs), and any compatibility notes (config schema, defaults, etc.).
- Do not include generated artifacts (e.g., `build/`, `cmake-build-release/`) in PRs.
- Feature-based workflow: never commit on `dev/integrated`; always commit on `feature/*`, then merge into `dev/integrated` (prefer fast-forward when possible).

## Security & Configuration Tips

- Avoid committing sensitive subscriber data/keys. Use `config/custom-*.yaml` as templates and keep local secrets in untracked files.
