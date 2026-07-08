#!/usr/bin/env sh
set -eu

if [ "${LSEC_RELEASE_ALLOW_UNTAGGED:-}" = "1" ]; then
  version="${VERSION:-$(cat VERSION)}"
else
  tag="$(git describe --tags --exact-match HEAD 2>/dev/null || true)"
  if [ -z "$tag" ]; then
    echo "build-release: refusing release build; HEAD is not exactly on a version tag. Set LSEC_RELEASE_ALLOW_UNTAGGED=1 for local/test builds." >&2
    exit 1
  fi
  case "$tag" in
    v[0-9]* | [0-9]*) ;;
    *)
      echo "build-release: refusing release build; tag '$tag' is not a version tag." >&2
      exit 1
      ;;
  esac
  if [ -n "$(git status --porcelain)" ]; then
    echo "build-release: refusing release build from a dirty working tree. Set LSEC_RELEASE_ALLOW_UNTAGGED=1 for local/test builds." >&2
    exit 1
  fi
  version="$tag"
fi
version="${version#v}"
commit="${COMMIT:-$(git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)}"
date="${DATE:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
dist="${DIST:-dist}"

case "$dist" in
  ""|.|..|/)
    echo "build-release: unsafe DIST '$dist'" >&2
    exit 1
    ;;
esac

dist_parent="$(dirname "$dist")"
dist_name="$(basename "$dist")"
case "$dist_name" in
  ""|.|..|/)
    echo "build-release: unsafe DIST '$dist'" >&2
    exit 1
    ;;
esac

mkdir -p "$dist_parent"
dist_parent="$(cd "$dist_parent" && pwd -P)"
dist="$dist_parent/$dist_name"
repo_root="$(pwd -P)"
case "$repo_root/" in
  "$dist/"*)
    echo "build-release: unsafe DIST '$dist'" >&2
    exit 1
    ;;
esac

work="$(mktemp -d "$dist_parent/.lsec-release.XXXXXX")"
output="$work/output"
published=0
cleanup() {
  if [ "$published" -eq 0 ] && [ -e "$work/previous" ] && [ ! -e "$dist" ]; then
    mv "$work/previous" "$dist"
  fi
  rm -rf "$work"
}
trap 'cleanup' EXIT HUP INT TERM
mkdir "$output"

ldflags="-s -w -X local-sec/internal/lsec.Version=${version} -X local-sec/internal/lsec.Commit=${commit} -X local-sec/internal/lsec.Date=${date}"

build_one() {
  goos="$1"
  goarch="$2"
  name="lsec_${version}_${goos}_${goarch}"
  binary="lsec"
  if [ "$goos" = "windows" ]; then
    binary="lsec.exe"
  fi
  tmp="$output/$name"
  mkdir -p "$tmp/docs"
  env CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" go build -trimpath -ldflags "$ldflags" -o "$tmp/$binary" ./cmd/lsec
  cp README.md "$tmp/"
  printf '%s\n' "$version" > "$tmp/VERSION"
  cp docs/technical-overview.md docs/roadmap.md "$tmp/docs/"
  tar -C "$output" -czf "$output/$name.tar.gz" "$name"
  rm -rf "$tmp"
}

build_one darwin arm64
build_one darwin amd64
build_one linux arm64
build_one linux amd64
build_one windows amd64

(cd "$output" && shasum -a 256 *.tar.gz > checksums.txt)

if [ -e "$dist" ]; then
  mv "$dist" "$work/previous"
fi
mv "$output" "$dist"
published=1
