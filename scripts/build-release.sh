#!/usr/bin/env bash
set -Eeuo pipefail
umask 022

project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
version="${1:-0.3.1}"
if [[ ! "$version" =~ ^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$ ]]; then
    printf 'Invalid version: use a Docker tag with letters, digits, _, . or -.\n' >&2
    exit 2
fi

image="${OTEL_UI_IMAGE:-traceyard:${version}}"
python_bin="${PYTHON:-python3}"
"$python_bin" -c 'import sys; assert sys.version_info >= (3, 11), "Python 3.11+ is required for archive packaging"'
platform="${PLATFORM:-$(docker version --format '{{.Server.Os}}/{{.Server.Arch}}')}"
case "$platform" in
    linux/amd64|linux/arm64) ;;
    *) printf 'Unsupported platform: %s (use linux/amd64 or linux/arm64).\n' "$platform" >&2; exit 2 ;;
esac

release_name="traceyard-${version}-${platform//\//-}"
dist_dir="${project_dir}/dist"
release_dir="${dist_dir}/${release_name}"
if [[ -e "$release_dir" ]]; then
    printf 'Release already exists: %s\nChoose a new version or move the old release first.\n' "$release_dir" >&2
    exit 2
fi

printf 'Building %s for %s\n' "$image" "$platform"
docker build --platform "$platform" --tag "$image" "$project_dir"
actual_platform="$(docker image inspect --format '{{.Os}}/{{.Architecture}}' "$image")"
if [[ "$actual_platform" != "$platform" ]]; then
    printf 'Image platform mismatch: requested %s, got %s\n' "$platform" "$actual_platform" >&2
    exit 1
fi

mkdir -p -- "$dist_dir"
stage_dir="$(mktemp -d "${dist_dir}/.traceyard-release.XXXXXX")"
cleanup() { rm -rf -- "$stage_dir"; }
trap cleanup EXIT
archive_name="${release_name}.tar.gz"
printf 'Exporting image to %s\n' "${release_dir}/${archive_name}"
docker save --output "${stage_dir}/.docker-save.tar" "$image"
"$python_bin" "${project_dir}/scripts/classic-docker-archive.py" \
    "${stage_dir}/.docker-save.tar" "${stage_dir}/${archive_name}" --tag "$image"
rm -- "${stage_dir}/.docker-save.tar"
mkdir -- "${stage_dir}/deploy"
cp -- "${project_dir}/README.md" "${stage_dir}/README.md"
cp -- "${project_dir}/LICENSE" "${stage_dir}/LICENSE"
cp -- "${project_dir}/VALIDATION.md" "${stage_dir}/VALIDATION.md"
mkdir -- "${stage_dir}/docs"
cp -- "${project_dir}/docs/screenshot.png" "${stage_dir}/docs/screenshot.png"
cp -- "${project_dir}/deploy/otel-ui.service" \
      "${project_dir}/deploy/otel-ui.env.example" \
      "${project_dir}/deploy/runtime.env.example" \
      "${project_dir}/deploy/argocd.yml" \
      "${project_dir}/deploy/requirements.yml" \
      "${project_dir}/deploy/values.example.yml" "${stage_dir}/deploy/"
mkdir -- "${stage_dir}/chart"
cp -- "${project_dir}/chart/Chart.yaml" "${project_dir}/chart/values.yaml" "${stage_dir}/chart/"
cp -R -- "${project_dir}/chart/templates" "${stage_dir}/chart/templates"
printf '# Runtime settings for this release; read by systemd.\nOTEL_UI_IMAGE=%s\nBIND_ADDRESS=127.0.0.1\nHOST_PORT=8080\n' \
    "$image" > "${stage_dir}/deploy/runtime.env.example"
{
    printf 'image=%s\n' "$image"
    printf 'image_id=%s\n' "$(docker image inspect --format '{{.Id}}' "$image")"
    printf 'platform=%s\n' "$actual_platform"
    printf 'archive_format=docker-classic\n'
    printf 'built_at_utc=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
} > "${stage_dir}/release.txt"
(
    cd -- "$stage_dir"
    find . -type f ! -name SHA256SUMS -print0 | LC_ALL=C sort -z | xargs -0 sha256sum -- > SHA256SUMS
)
mv -T -- "$stage_dir" "$release_dir"
trap - EXIT
printf '\nRelease ready: %s\nCopy this directory to the node; follow README.md.\n' "$release_dir"
