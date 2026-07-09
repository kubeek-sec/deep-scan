# Deep Scan kruncher image: core engine + CLI + kruncher + admin in one image.
# Build from the repo root:  docker build -f deploy/docker/Dockerfile -t kubeek-sec/deepscan .
#
# The same image runs every role; the container command picks one:
#   deepscan-kruncher worker | scheduler | run | run-one
#   deepscan-kruncher-admin
#   deepscan  (the scanner CLI)

# --------------------------------------------------------------------------- #
# Stage 1: resolve and install the workspace into a self-contained venv.
# --------------------------------------------------------------------------- #
FROM ghcr.io/astral-sh/uv:python3.13-bookworm-slim AS builder

ENV UV_LINK_MODE=copy \
    UV_COMPILE_BYTECODE=1 \
    UV_PYTHON_DOWNLOADS=never

WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
COPY packages ./packages
# Install only the dependency graph we ship (no dev group) into /app/.venv.
RUN uv sync --frozen --no-dev --no-editable

# --------------------------------------------------------------------------- #
# Stage 2: slim runtime.
# --------------------------------------------------------------------------- #
FROM python:3.13-slim-bookworm AS runtime

# git: ls-remote + clone for the git connectors. ca-certificates: TLS to APIs.
# nodejs: CodeQL's JavaScript extractor shells out to Node.js for *TypeScript*
# extraction - without `node` on PATH, `codeql database create --language
# javascript` fails on any project containing .ts/.tsx ("Could not start
# Node.js. It is required for TypeScript extraction."). Plain JS does not need it.
RUN apt-get update && apt-get install -y --no-install-recommends \
        git ca-certificates curl nodejs \
    && rm -rf /var/lib/apt/lists/*

ENV PATH="/home/deepscan/.local/bin:/app/.venv/bin:$PATH" \
    HOME=/home/deepscan \
    DEEPSCAN_TOOLS_DIR=/opt/deepscan/tools \
    DEEPSCAN_KRUNCHER_WORK_DIR=/tmp/deepscan-work \
    PYTHONUNBUFFERED=1

# Non-root by default.
RUN useradd --create-home --uid 10001 deepscan \
    && mkdir -p /opt/deepscan/tools /tmp/deepscan-work \
    && chown -R deepscan:deepscan /opt/deepscan /tmp/deepscan-work

COPY --from=builder /app /app
# uv: lets the UV-managed scanners (e.g. cisco-ai-skill-scanner) install & run.
COPY --from=builder /usr/local/bin/uv /usr/local/bin/uvx /usr/local/bin/
COPY deploy/docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# Optional: ClamAV (malware family). Heavy - pulls the OS package + a virus-DB
# snapshot - so it is off by default; the docker-compose build turns it on.
# Runs as root (apt) before dropping to the non-root user.
ARG INSTALL_CLAMAV=false
RUN if [ "$INSTALL_CLAMAV" = "true" ]; then \
        deepscan tools install clamav \
        || echo "WARN: clamav install/DB update failed; the 'clamav' scanner will skip"; \
        rm -rf /var/lib/apt/lists/*; \
    fi

# Optionally bake the pinned, checksum-verified scanner binaries into the image
# (SAST/SCA/secret/IaC). Skip with --build-arg INSTALL_TOOLS=false for a thin
# image that installs tools at runtime into a mounted DEEPSCAN_TOOLS_DIR.
# CodeQL is included here but stays inert unless enabled with CODEQL=true (the
# scanner is off by default), so baking it costs disk but never runs unasked.
ARG INSTALL_TOOLS=true
USER deepscan
RUN if [ "$INSTALL_TOOLS" = "true" ]; then \
        deepscan tools install all || echo "WARN: tool install skipped/failed; install at runtime"; \
    fi

# Optional: cisco-ai-skill-scanner (SAST - AI agent skill threats), a uv-managed
# tool. Off by default; the docker-compose build turns it on.
ARG INSTALL_CISCO_SKILL=false
RUN if [ "$INSTALL_CISCO_SKILL" = "true" ]; then \
        deepscan tools install cisco-ai-skill-scanner \
        || echo "WARN: cisco-ai-skill-scanner install failed; that scanner will skip"; \
    fi

# Optional: checkov (IaC misconfiguration), a uv-managed tool. Off by default;
# the docker-compose build turns it on.
ARG INSTALL_CHECKOV=false
RUN if [ "$INSTALL_CHECKOV" = "true" ]; then \
        deepscan tools install checkov \
        || echo "WARN: checkov install failed; that scanner will skip"; \
    fi

# Optional: pre-fetch nuclei DAST templates (the separate nuclei-templates repo,
# ~hundreds of MB) so dynamic scans have rules without a runtime download. Off by
# default; the docker-compose build enables it. Lands under $HOME, used at runtime.
ARG INSTALL_NUCLEI_TEMPLATES=false
RUN if [ "$INSTALL_NUCLEI_TEMPLATES" = "true" ]; then \
        NUCLEI="$(python -c 'from deepscan_core.install import tool_path; print(tool_path("nuclei") or "")')"; \
        if [ -n "$NUCLEI" ]; then \
            "$NUCLEI" -update-templates -no-color \
            || echo "WARN: nuclei template fetch failed; DAST will skip until templates exist"; \
        else echo "WARN: nuclei not installed; skipping template fetch"; fi; \
    fi

# Optional: install the Claude Code CLI for the off-by-default `ai-analysis`
# triage scanner (`--scanner ai-analysis` / AI_ANALYSIS=true). Build with
# --build-arg INSTALL_CLAUDE=true. Point it at a local model at runtime
# (ANTHROPIC_BASE_URL / DEEPSCAN_CLAUDE_SETTINGS).
ARG INSTALL_CLAUDE=false
RUN if [ "$INSTALL_CLAUDE" = "true" ]; then \
        curl -fsSL https://claude.ai/install.sh | bash \
        || echo "WARN: Claude CLI install failed; the 'ai-analysis' scanner will skip"; \
    fi

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["deepscan-kruncher", "run"]
