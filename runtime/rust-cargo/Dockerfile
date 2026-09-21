FROM rust:1.95-bookworm@sha256:6258907abe69656e41cd992e0b705cdcfabcbbe3db374f92ed2d47121282d4a1 AS vendor

ARG PROBE_MANIFEST_PATH
ARG PROBE_LOCK_PATH
COPY .rust-runtime-target /source
WORKDIR /source
RUN test -n "$PROBE_MANIFEST_PATH" \
    && test -n "$PROBE_LOCK_PATH" \
    && test "$(dirname "$PROBE_MANIFEST_PATH")/Cargo.lock" = "$PROBE_LOCK_PATH" \
    && test -f "$PROBE_MANIFEST_PATH" \
    && test -f "$PROBE_LOCK_PATH" \
    && mkdir -p /opt/elevenid/vendor \
    && cargo vendor --locked --versioned-dirs \
      --manifest-path "$PROBE_MANIFEST_PATH" /opt/elevenid/vendor \
      > /opt/elevenid/cargo-config.toml \
    && cp "$PROBE_LOCK_PATH" /opt/elevenid/Cargo.lock

FROM rust:1.95-bookworm@sha256:6258907abe69656e41cd992e0b705cdcfabcbbe3db374f92ed2d47121282d4a1

ARG PROBE_REPOSITORY
ARG PROBE_REVISION
ARG PROBE_MANIFEST_PATH
ARG PROBE_MANIFEST_SHA256
ARG PROBE_LOCK_PATH
ARG PROBE_LOCK_SHA256
ARG PROBE_SUBJECT_PATH
ARG PROBE_SUBJECT_SHA256
ARG BUILDX_VERSION
ARG BUILDKIT_IMAGE
ARG SBOM_GENERATOR
LABEL org.opencontainers.image.source="https://github.com/ElevenID/.github" \
    io.elevenid.feature-regression.probe.repository="$PROBE_REPOSITORY" \
    io.elevenid.feature-regression.probe.revision="$PROBE_REVISION" \
    io.elevenid.feature-regression.probe.manifest="$PROBE_MANIFEST_PATH" \
    io.elevenid.feature-regression.probe.manifest-sha256="$PROBE_MANIFEST_SHA256" \
    io.elevenid.feature-regression.probe.lock="$PROBE_LOCK_PATH" \
    io.elevenid.feature-regression.probe.lock-sha256="$PROBE_LOCK_SHA256" \
    io.elevenid.feature-regression.probe.subject="$PROBE_SUBJECT_PATH" \
    io.elevenid.feature-regression.probe.subject-sha256="$PROBE_SUBJECT_SHA256" \
    io.elevenid.feature-regression.probe.builder.buildx-version="$BUILDX_VERSION" \
    io.elevenid.feature-regression.probe.builder.buildkit-image="$BUILDKIT_IMAGE" \
    io.elevenid.feature-regression.probe.builder.sbom-generator="$SBOM_GENERATOR"

RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=vendor /opt/elevenid /opt/elevenid
COPY runtime/rust-cargo/run-rust-probe /opt/elevenid/bin/run-rust-probe
RUN chmod 0555 /opt/elevenid/bin/run-rust-probe \
    && python3 - <<'PY'
import hashlib
import json
import pathlib
import subprocess

root = pathlib.Path("/opt/elevenid")
document = {
    "cargo_version": subprocess.check_output(
        ["/usr/local/cargo/bin/cargo", "--version"], text=True
    ).strip(),
    "profile": "rust-cargo-v1",
    "python_version": subprocess.check_output(
        ["/usr/bin/python3", "--version"], text=True, stderr=subprocess.STDOUT
    ).strip(),
    "rustc_version": subprocess.check_output(
        ["/usr/local/cargo/bin/rustc", "--version", "--verbose"], text=True
    ).strip(),
    "schema": "elevenid.rust-cargo-runtime/v1",
    "vendor_lock_sha256": "sha256:" + hashlib.sha256(
        (root / "Cargo.lock").read_bytes()
    ).hexdigest(),
    "wrapper_sha256": "sha256:" + hashlib.sha256(
        (root / "bin" / "run-rust-probe").read_bytes()
    ).hexdigest(),
}
(root / "runtime-manifest.json").write_bytes(
    json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
)
PY

USER 65534:65534
WORKDIR /build
ENTRYPOINT []
