#!/bin/sh

ARCH=$(uname -m); URL="https://storage.googleapis.com/gvisor/releases/release/latest/${ARCH}"
for f in runsc containerd-shim-runsc-v1; do
  wget "${URL}/${f}" "${URL}/${f}.sha512"; sha512sum -c "${f}.sha512"
  chmod a+rx "$f"; sudo mv "$f" /usr/local/bin/; done
sudo /usr/local/bin/runsc install && sudo systemctl reload docker
