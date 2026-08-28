# OpenTofu Runner Dockerfile
# This builds the self-hosted runner that executes OpenTofu plans/applies.
# NOTE: This Dockerfile must be built from the repository root (context = repo root)
#
# Stackweaver runs OpenTofu (MPL-2.0) and never Terraform. Terraform >= 1.6 is BUSL-1.1 licensed,
# under which "Embedded" explicitly covers packaging a competitive offering such that the Licensed
# Work must be downloaded for it to operate - so neither this image nor any runtime code path may
# fetch it. See docs/internal/plans/features/terraform/opentofu-migration-plan.md.
#
# Example: docker build -f runner-images/opentofu/Dockerfile -t stackweaver/runner-opentofu:latest .

# Build stage
FROM golang:1.26.6-alpine@sha256:3889b425f035be855a72fb4755265311293b6d414521f0a519d819df32222d83 AS builder
ENV GOPRIVATE=github.com/michielvha/stackweaver

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git

# Copy go modules first for caching
COPY backend/go.mod backend/go.sum ./
RUN --mount=type=secret,id=netrc,target=/root/.netrc go mod download

# Copy source code
COPY backend/ .

# Build the runner binary (the OpenTofu runner uses cmd/runner)
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o runner ./cmd/runner

# Runtime stage - Chainguard wolfi-base: zero-CVE target, has shell + apk, glibc-based
FROM cgr.dev/chainguard/wolfi-base@sha256:8e8fe4b9b989b03daaa4305dba54a1b480f63716c56dc6bb074e5a6057bf3c73

# Build arguments for the baked-in OpenTofu version and architecture.
# Other catalogued versions are downloaded (and checksum-verified) on first use at run time
# by core/tofu; this one ships in the image so the common path needs no network.
ARG TARGETARCH
ARG TOFU_VERSION=1.12.5

# Install runtime dependencies, then remove build-only tools
# Install OpenTofu, verifying the archive against the release's published SHA256SUMS before
# trusting an executable we then run (AUD-058: TLS alone is not integrity).
RUN apk add --no-cache git ca-certificates wget unzip && \
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

USER stackweaver

# Create workspaces directory
RUN mkdir -p /home/stackweaver/workspaces

# Copy the runner binary from builder
COPY --from=builder /app/runner /usr/local/bin/runner

# Set working directory
WORKDIR /home/stackweaver

# Environment variables
ENV WORKSPACES_DIR=/home/stackweaver/workspaces

# Run the runner
CMD ["/usr/local/bin/runner"]
