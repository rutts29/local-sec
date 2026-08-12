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

case "$version" in
  ""|*[!ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.+-]*)
    echo "build-release: invalid version '$version'" >&2
    exit 1
    ;;
esac
if ! printf '%s\n' "$version" | LC_ALL=C grep -Eq '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z]+([.-][0-9A-Za-z]+)*)?(\+[0-9A-Za-z]+([.-][0-9A-Za-z]+)*)?$'; then
  echo "build-release: invalid version '$version'" >&2
  exit 1
fi

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

if [ -e "$dist" ]; then
  echo "build-release: refusing to overwrite existing DIST '$dist'" >&2
  exit 1
fi

work="$(mktemp -d "$dist_parent/.lsec-release.XXXXXX")"
output="$work/output"
cleanup() {
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
  cp README.md SECURITY.md "$tmp/"
  printf '%s\n' "$version" > "$tmp/VERSION"
  cp docs/technical-overview.md docs/roadmap.md docs/threat-model-and-limitations.md "$tmp/docs/"
  env COPYFILE_DISABLE=1 COPY_EXTENDED_ATTRIBUTES_DISABLE=1 tar --format ustar --exclude '*/._*' -C "$output" -czf "$output/$name.tar.gz" "$name"
  rm -rf "$tmp"
}

build_one darwin arm64
build_one darwin amd64
build_one linux arm64
build_one linux amd64
build_one windows amd64

(cd "$output" && shasum -a 256 *.tar.gz > checksums.txt)

mv "$output" "$dist"
