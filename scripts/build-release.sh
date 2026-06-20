#!/usr/bin/env sh
set -eu

version="${VERSION:-$(cat VERSION)}"
version="${version#v}"
commit="${COMMIT:-$(git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)}"
date="${DATE:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
dist="${DIST:-dist}"

rm -rf "$dist"
mkdir -p "$dist"

ldflags="-s -w -X local-sec/internal/lsec.Version=${version} -X local-sec/internal/lsec.Commit=${commit} -X local-sec/internal/lsec.Date=${date}"

build_one() {
  goos="$1"
  goarch="$2"
  name="lsec_${version}_${goos}_${goarch}"
  binary="lsec"
  if [ "$goos" = "windows" ]; then
    binary="lsec.exe"
  fi
  tmp="$dist/$name"
  mkdir -p "$tmp"
  env CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" go build -trimpath -ldflags "$ldflags" -o "$tmp/$binary" ./cmd/lsec
  cp README.md VERSION "$tmp/"
  tar -C "$dist" -czf "$dist/$name.tar.gz" "$name"
  rm -rf "$tmp"
}

build_one darwin arm64
build_one darwin amd64
build_one linux arm64
build_one linux amd64
build_one windows amd64

(cd "$dist" && shasum -a 256 *.tar.gz > checksums.txt)
