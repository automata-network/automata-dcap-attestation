# Pin both the base image and platform. The final built image ID must also be
# recorded and reused for both runs; never install a compiler during a run.
FROM --platform=linux/arm64 rust@sha256:b1b3c9c0d921d7fa0a6d1f9ec7e4eab87f8c8ec97644c3d791450f131dec813f
RUN RUSTUP_USE_CURL=1 rustup toolchain install nightly-2025-08-04 --profile minimal --component rust-src --no-self-update
RUN rustc +nightly-2025-08-04 --version | grep -F '1.91.0-nightly (f34ba774c 2025-08-03)'
