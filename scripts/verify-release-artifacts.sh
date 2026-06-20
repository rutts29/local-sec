#!/usr/bin/env sh
set -eu

dist="${DIST:-dist}"
version="${VERSION:-$(cat VERSION)}"
version="${version#v}"
test -s "$dist/checksums.txt"
(cd "$dist" && shasum -a 256 -c checksums.txt)

for target in darwin_amd64 darwin_arm64 linux_amd64 linux_arm64 windows_amd64; do
  name="lsec_${version}_${target}"
  archive="$dist/$name.tar.gz"
  test -s "$archive"
  tar -tzf "$archive" "$name/README.md" >/dev/null
  tar -tzf "$archive" "$name/VERSION" >/dev/null
  binary="lsec"
  case "$target" in
    windows_amd64) binary="lsec.exe" ;;
  esac
  tar -tzf "$archive" "$name/$binary" >/dev/null
done
