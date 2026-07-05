#!/usr/bin/env bash
#
# Installs every recon tool snitch orchestrates on Debian / Kali / Ubuntu.
# Precompiled packages come from apt; the few that aren't packaged come from
# `go install`. Run once, then `make build`.

set -euo pipefail

echo "[*] Installing packaged tools from apt (precompiled) ..."
sudo apt-get update -qq
sudo apt-get install -y golang-go git nmap ffuf sqlmap \
    subfinder httpx-toolkit naabu nuclei

echo "[*] Linking ProjectDiscovery httpx (avoids the Python httpx clash) ..."
sudo ln -sf "$(command -v httpx-toolkit)" /usr/local/bin/httpx

echo "[*] Installing the tools not in apt via go install (katana, dalfox, crlfuzz)."
echo "    This compiles from source and can take a few minutes ..."
set +e
for mod in \
    github.com/projectdiscovery/katana/cmd/katana@latest \
    github.com/hahwul/dalfox/v2@latest \
    github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest; do
    echo "    go install $mod"
    go install "$mod" || echo "    [!] failed (optional): $mod — retry later if you want it"
done
set -e

GOBIN="$(go env GOPATH)/bin"
export PATH="$PATH:$GOBIN"
if ! grep -qs "$GOBIN" "$HOME/.bashrc"; then
    echo "export PATH=\"\$PATH:$GOBIN\"" >>"$HOME/.bashrc"
    echo "[*] Added $GOBIN to PATH in ~/.bashrc (run 'source ~/.bashrc' or open a new shell)."
fi

echo "[*] Fetching nuclei templates ..."
nuclei -update-templates || true

echo
echo "[+] All set. Build snitch with:  make build  &&  ./snitch version"
