<div align="center">

<img src="https://raw.githubusercontent.com/vhco-pro/.github/main/profile/assets/stackweaver.png" alt="Stackweaver" width="150" />

# Stackweaver OpenTofu Runner

[![Release](https://github.com/vhco-pro/stackweaver-opentofu-runner/actions/workflows/release.yml/badge.svg)](https://github.com/vhco-pro/stackweaver-opentofu-runner/actions/workflows/release.yml)
[![Latest Release](https://img.shields.io/github/v/release/vhco-pro/stackweaver-opentofu-runner?sort=semver)](https://github.com/vhco-pro/stackweaver-opentofu-runner/releases/latest)
[![CodeQL](https://github.com/vhco-pro/stackweaver-opentofu-runner/actions/workflows/codeql.yml/badge.svg)](https://github.com/vhco-pro/stackweaver-opentofu-runner/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/vhco-pro/stackweaver-opentofu-runner/badge)](https://scorecard.dev/viewer/?uri=github.com/vhco-pro/stackweaver-opentofu-runner)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)
[![Docs](https://img.shields.io/badge/docs-stackweaver.sh-0ea5e9)](https://stackweaver.sh/docs)

The self-hosted OpenTofu runner for the [Stackweaver](https://stackweaver.sh) DevOps platform.

</div>

This is the public release repository for the Stackweaver OpenTofu Runner. It is published from the Stackweaver source tree on every release. See the [release sync architecture](https://stackweaver.sh/docs/security/sync-architecture) for how releases are built, signed, and mirrored here.

## Overview

This runner executes OpenTofu plan/apply/destroy operations as part of the Stackweaver orchestration pipeline. It connects to the Stackweaver API via Redis queue, receives jobs, and streams logs back in real-time.

## Usage

```bash
docker pull ghcr.io/vhco-pro/stackweaver-opentofu-runner:latest
```

See the [Stackweaver documentation](https://stackweaver.sh/docs) for deployment and configuration instructions.

## License

Apache License 2.0 — see [LICENSE](LICENSE) for details.
