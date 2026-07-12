#!/usr/bin/env bash
#
# Downloads the latest Hayabusa release for the current platform and
# extracts it to ./hayabusa/. Safe to re-run to upgrade to the latest version.
set -euo pipefail

REPO="Yamato-Security/hayabusa"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
DEST_DIR="${ROOT_DIR}/hayabusa"

for cmd in curl unzip python3; do
    if ! command -v "${cmd}" >/dev/null 2>&1; then
        echo "error: required command '${cmd}' not found" >&2
        exit 1
    fi
done

os="$(uname -s)"
arch="$(uname -m)"

case "${os}" in
    Linux)
        case "${arch}" in
            x86_64) asset_suffix="lin-x64-musl" ;;
            aarch64|arm64) asset_suffix="lin-aarch64-gnu" ;;
            *) echo "error: unsupported Linux architecture '${arch}'" >&2; exit 1 ;;
        esac
        ;;
    Darwin)
        case "${arch}" in
            x86_64) asset_suffix="mac-x64" ;;
            arm64) asset_suffix="mac-aarch64" ;;
            *) echo "error: unsupported macOS architecture '${arch}'" >&2; exit 1 ;;
        esac
        ;;
    *)
        echo "error: unsupported platform '${os}' (this script supports Linux and macOS)" >&2
        exit 1
        ;;
esac

echo "Detected platform: ${os} ${arch} (asset suffix: ${asset_suffix})"

echo "Looking up latest Hayabusa release..."
release_json="$(curl -sS -f "https://api.github.com/repos/${REPO}/releases/latest")" || {
    echo "error: failed to query GitHub releases API for ${REPO}" >&2
    exit 1
}

release_info="$(python3 -c "
import json, sys

data = json.loads(sys.stdin.read())
suffix = '${asset_suffix}'
tag = data.get('tag_name', '?')
for asset in data.get('assets', []):
    name = asset['name']
    if name.endswith(f'-{suffix}.zip'):
        print(tag, asset['browser_download_url'])
        break
else:
    sys.exit(1)
" <<< "${release_json}")" || true

version="$(cut -d' ' -f1 <<< "${release_info}")"
download_url="$(cut -d' ' -f2 <<< "${release_info}")"

if [[ -z "${download_url:-}" ]]; then
    echo "error: no release asset found for suffix '${asset_suffix}'" >&2
    exit 1
fi

echo "Latest version: ${version}"
echo "Asset URL: ${download_url}"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT

zip_path="${tmp_dir}/hayabusa.zip"
echo "Downloading..."
curl -sS -f -L -o "${zip_path}" "${download_url}" || {
    echo "error: failed to download ${download_url}" >&2
    exit 1
}

rm -rf "${DEST_DIR}"
mkdir -p "${DEST_DIR}"

echo "Extracting to ${DEST_DIR}..."
unzip -q "${zip_path}" -d "${DEST_DIR}" || {
    echo "error: failed to extract ${zip_path}" >&2
    exit 1
}

binary_path="$(find "${DEST_DIR}" -maxdepth 1 -type f -name "hayabusa-*-${asset_suffix}" | head -n1)"
if [[ -z "${binary_path}" ]]; then
    echo "error: could not locate Hayabusa binary inside extracted archive" >&2
    exit 1
fi

chmod +x "${binary_path}"
ln -sf "$(basename "${binary_path}")" "${DEST_DIR}/hayabusa"

echo "Hayabusa ${version} installed at ${DEST_DIR}/hayabusa"
"${DEST_DIR}/hayabusa" help | head -n1 || true
