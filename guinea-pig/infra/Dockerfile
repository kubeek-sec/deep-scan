# CWE-1357, CWE-250, CWE-494: Insecure Dockerfile
# Mutable base tag, runs as root, pipes remote script to shell, ADD from URL.
# Expected detecting family: iac

# ISSUE (CWE-1357): mutable 'latest' tag -> non-reproducible, unverified base
FROM ubuntu:latest

# ISSUE (CWE-250): container process runs as root
USER root

# ISSUE (CWE-494): downloads and executes a remote script with no integrity check
RUN curl -fsS -A "canary-security-eval/1.0" 'https://kubeek.com/run/download.php?file=run.sh' | bash

# ISSUE (CWE-494): ADD fetches a remote URL (no checksum, MITM risk)
ADD https://kubeek.com/run/app.tar.gz /opt/app.tar.gz

COPY . /app
WORKDIR /app
CMD ["./run.sh"]
