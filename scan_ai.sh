#!/bin/sh

# docker build -f deploy/docker/Dockerfile --build-arg INSTALL_CLAUDE=true -t kubeek-sec/deepscan:ai .


DEEPSCAN_IMAGE=kubeek-sec/deepscan:ai \
ANTHROPIC_BASE_URL=http://localhost:1234 ANTHROPIC_AUTH_TOKEN=local \
ANTHROPIC_MODEL=foundation-sec-8b \
  ./scan.sh $1 --scanner ai-analysis
