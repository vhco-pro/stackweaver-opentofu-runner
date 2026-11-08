# OpenTofu job image Dockerfile
# This builds the OpenTofu job image: the image OpenTofu runs execute in, which also starts an
# in-process launcher for OpenTofu by default (one-launcher spec, A5, OD4).
# NOTE: This Dockerfile must be built from the repository root (context = repo root)
#
# Stackweaver runs OpenTofu (MPL-2.0) and never Terraform. Terraform >= 1.6 is BUSL-1.1 licensed,
# under which "Embedded" explicitly covers packaging a competitive offering such that the Licensed
# Work must be downloaded for it to operate - so neither this image nor any runtime code path may
# fetch it. See docs/internal/plans/features/terraform/opentofu-migration-plan.md.
#
# Example: docker build -f runner-images/opentofu/Dockerfile -t stackweaver/runner-opentofu:latest .

# Build stage
FROM golang:1.27.3-alpine@sha256:b8c9b82affbbb82a020bbcf998dad2ba9516944ac7e883524642a481a9505e9c AS builder
ENV GOPRIVATE=github.com/michielvha/stackweaver

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git

# Copy go modules first for caching
COPY backend/go.mod backend/go.sum ./
RUN --mount=type=secret,id=netrc,target=/root/.netrc go mod download

# Copy source code
COPY backend/ .

# Build the launcher binary, which carries every engine's executor; VERSION is the release it
# reports.
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags "-X main.version=${VERSION}" -o stackweaver-launcher ./cmd/launcher

# Runtime stage - Chainguard wolfi-base: zero-CVE target, has shell + apk, glibc-based
FROM cgr.dev/chainguard/wolfi-base@sha256:c2a4815b6ca49b9bbafd451b4bde690d567a86b2b6b54877faac8082a7bc4296

# Build arguments for the baked-in OpenTofu version and architecture.
# Other catalogued versions are downloaded (and checksum-verified) on first use at run time
# by core/tofu; this one ships in the image so the common path needs no network.
ARG TARGETARCH
ARG TOFU_VERSION=1.13.1

# Install runtime dependencies, then remove build-only tools
# Install OpenTofu, verifying the archive against the release's published SHA256SUMS before
# trusting an executable we then run (AUD-058: TLS alone is not integrity).
# cosign verifies each OpenTofu release a launcher's populator promotes into an organization's
# cache (#933, D7).
RUN apk add --no-cache git ca-certificates wget unzip iptables ip6tables nftables cosign && \
    ARCH=$(case ${TARGETARCH:-amd64} in amd64) echo "amd64" ;; arm64) echo "arm64" ;; *) echo "amd64" ;; esac) && \
    BASE="https://github.com/opentofu/opentofu/releases/download/v${TOFU_VERSION}" && \
    ZIP="tofu_${TOFU_VERSION}_linux_${ARCH}.zip" && \
    wget -q "${BASE}/${ZIP}" -O /tmp/tofu.zip && \
    wget -q "${BASE}/tofu_${TOFU_VERSION}_SHA256SUMS" -O /tmp/tofu.sums && \
    echo "$(grep "  ${ZIP}\$" /tmp/tofu.sums | cut -d' ' -f1)  /tmp/tofu.zip" | sha256sum -c - && \
    unzip -o /tmp/tofu.zip tofu -d /usr/local/bin && \
    mv /usr/local/bin/tofu /usr/local/bin/tofu-${TOFU_VERSION} && \
    ln -sf /usr/local/bin/tofu-${TOFU_VERSION} /usr/local/bin/tofu && \
    rm -f /tmp/tofu.zip /tmp/tofu.sums && \
    apk del wget unzip && \
    tofu version

# Create non-root user with UID 1001 to match ansible runner. The UID, not the name, is what
# matters for the shared workspaces volume - it stayed 1001 across the iac -> stackweaver rename.
RUN addgroup -g 1001 stackweaver && \
    adduser -D -u 1001 -G stackweaver -h /home/stackweaver stackweaver

# A launcher's node-local, read-only cache copy (RUNNER_CACHE_DIR): owned by the image's user, so a
# named volume mounted here starts out writable by an in-process launcher too.
RUN mkdir -p /var/cache/stackweaver-launcher && chown stackweaver:stackweaver /var/cache/stackweaver-launcher

# The launcher binary at the constant executor path, and a link at the old path, so an older
# launcher that runs `/usr/local/bin/runner executor` in this image still starts its executor.
COPY --from=builder /app/stackweaver-launcher /usr/local/bin/stackweaver-launcher
RUN ln -s stackweaver-launcher /usr/local/bin/runner

USER stackweaver

# Create workspaces directory
RUN mkdir -p /home/stackweaver/workspaces

# Set working directory
WORKDIR /home/stackweaver

# Environment variables
ENV WORKSPACES_DIR=/home/stackweaver/workspaces

# Start an in-process launcher for OpenTofu
CMD ["/usr/local/bin/stackweaver-launcher"]
