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

FROM python:3.11.16-bookworm@sha256:b99029c95d3d37fb1e4e76d287f7984373dca77c665885986e31b2c95260c13c

ENV RUSTUP_HOME=/usr/local/rustup \
    PATH=/usr/local/cargo/bin:$PATH

ARG PROBE_REPOSITORY
ARG PROBE_REVISION
ARG PROBE_MANIFEST_PATH
ARG PROBE_MANIFEST_SHA256
ARG PROBE_LOCK_PATH
ARG PROBE_LOCK_SHA256
ARG PROBE_SUBJECT_PATH
ARG PROBE_SUBJECT_SHA256
ARG BUILDX_VERSION
ARG BUILDX_SHA256
ARG BUILDKIT_IMAGE
ARG SBOM_GENERATOR
ARG SBOM_GENERATOR_LINUX_AMD64_DIGEST
ARG PYTHON_BASE_IMAGE
ARG PYTHON_BASE_LINUX_AMD64_DIGEST
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
    io.elevenid.feature-regression.probe.builder.buildx-sha256="$BUILDX_SHA256" \
    io.elevenid.feature-regression.probe.builder.buildkit-image="$BUILDKIT_IMAGE" \
    io.elevenid.feature-regression.probe.builder.sbom-generator="$SBOM_GENERATOR" \
    io.elevenid.feature-regression.probe.builder.sbom-generator-linux-amd64-digest="$SBOM_GENERATOR_LINUX_AMD64_DIGEST" \
    io.elevenid.feature-regression.probe.runtime.python-base-image="$PYTHON_BASE_IMAGE" \
    io.elevenid.feature-regression.probe.runtime.python-base-linux-amd64-digest="$PYTHON_BASE_LINUX_AMD64_DIGEST"

COPY --from=vendor /opt/elevenid /opt/elevenid
COPY --from=vendor /usr/local/cargo/bin /usr/local/cargo/bin
COPY --from=vendor /usr/local/rustup /usr/local/rustup
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
        ["/usr/local/bin/python3", "--version"], text=True, stderr=subprocess.STDOUT
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
