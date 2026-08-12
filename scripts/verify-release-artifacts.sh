#!/usr/bin/env sh
set -eu

dist="${DIST:-dist}"
version="${VERSION:-$(cat VERSION)}"
version="${version#v}"

case "$version" in
  ""|*[!ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.+-]*)
    echo "verify-release-artifacts: invalid version '$version'" >&2
    exit 1
    ;;
esac
if ! printf '%s\n' "$version" | LC_ALL=C grep -Eq '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z]+([.-][0-9A-Za-z]+)*)?(\+[0-9A-Za-z]+([.-][0-9A-Za-z]+)*)?$'; then
  echo "verify-release-artifacts: invalid version '$version'" >&2
  exit 1
fi

test -s "$dist/checksums.txt"

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/lsec-release-verify.XXXXXX")"
trap 'rm -rf "$tmp_dir"' EXIT HUP INT TERM

tar_member_mode() {
  archive="$1"
  member="$2"
  listing="$tmp_dir/member-mode"
  tar -tvzf "$archive" "$member" > "$listing"
  awk '{print $1; exit}' "$listing"
}

require_regular_member() {
  archive="$1"
  member="$2"
  mode="$(tar_member_mode "$archive" "$member")"
  case "$mode" in
    -*) ;;
    *)
      echo "$archive $member is not a regular file" >&2
      exit 1
      ;;
  esac
}

require_directory_member() {
  archive="$1"
  member="$2"
  mode="$(tar_member_mode "$archive" "$member")"
  case "$mode" in
    d*) ;;
    *)
      echo "$archive $member is not a directory" >&2
      exit 1
      ;;
  esac
}

require_readme_linked_member() {
  archive="$1"
  member="$2"
  if ! tar -tzf "$archive" "$member" >/dev/null 2>&1; then
    echo "$archive README.md links to missing archive member: $member" >&2
    exit 1
  fi
  require_regular_member "$archive" "$member"
}

reject_appledouble_members() {
  archive="$1"
  members="$2"
  awk -v archive="$archive" '
    {
      count = split($0, parts, "/")
      if (parts[count] ~ /^\._/) {
        print archive " contains AppleDouble archive member: " $0 > "/dev/stderr"
        failed = 1
      }
    }
    END { exit failed }
  ' "$members"
}

physical_archives="$tmp_dir/physical-archives"
: > "$physical_archives"
for archive in "$dist"/*.tar.gz "$dist"/.[!.]*.tar.gz "$dist"/..?*.tar.gz; do
  case "$(basename "$archive")" in
    "*.tar.gz"|".[!.]*.tar.gz"|"..?*.tar.gz")
      continue
      ;;
  esac
  if [ ! -e "$archive" ] && [ ! -L "$archive" ]; then
    continue
  fi
  if [ ! -f "$archive" ] || [ -L "$archive" ]; then
    echo "DIST archive is not a physical regular file: $archive" >&2
    exit 1
  fi
  basename "$archive" >> "$physical_archives"
done

awk -v version="$version" '
  BEGIN {
    n = split("darwin_amd64 darwin_arm64 linux_amd64 linux_arm64 windows_amd64", targets, " ")
    for (i = 1; i <= n; i++) {
      required["lsec_" version "_" targets[i] ".tar.gz"] = 1
    }
  }
  {
    archive = $0
    seen[archive]++
    if (!(archive in required)) {
      print "DIST contains unexpected archive: " archive > "/dev/stderr"
      failed = 1
    }
  }
  END {
    for (archive in required) {
      if (seen[archive] == 0) {
        print "DIST is missing archive: " archive > "/dev/stderr"
        failed = 1
      } else if (seen[archive] != 1) {
        print "DIST contains duplicate archive: " archive > "/dev/stderr"
        failed = 1
      }
    }
    exit failed
  }
' "$physical_archives"

awk -v version="$version" '
  BEGIN {
    n = split("darwin_amd64 darwin_arm64 linux_amd64 linux_arm64 windows_amd64", targets, " ")
    for (i = 1; i <= n; i++) {
      required["lsec_" version "_" targets[i] ".tar.gz"] = 1
    }
  }
  {
    hash = $1
    archive = $2
    if (NF != 2 || length(hash) != 64 || hash ~ /[^0-9a-f]/ || $0 != hash "  " archive) {
      print "checksums.txt contains invalid checksum line: " $0 > "/dev/stderr"
      failed = 1
      next
    }
    seen[archive]++
    if (!(archive in required)) {
      print "checksums.txt contains unexpected archive: " archive > "/dev/stderr"
      failed = 1
    }
  }
  END {
    for (archive in required) {
      if (seen[archive] == 0) {
        print "checksums.txt is missing archive: " archive > "/dev/stderr"
        failed = 1
      } else if (seen[archive] != 1) {
        print "checksums.txt contains duplicate archive: " archive > "/dev/stderr"
        failed = 1
      }
    }
    exit failed
  }
' "$dist/checksums.txt"

(cd "$dist" && shasum -a 256 -c checksums.txt)

for target in darwin_amd64 darwin_arm64 linux_amd64 linux_arm64 windows_amd64; do
  name="lsec_${version}_${target}"
  archive="$dist/$name.tar.gz"
  test -s "$archive"
  binary="lsec"
  case "$target" in
    windows_amd64) binary="lsec.exe" ;;
  esac
  members="$tmp_dir/$target.members"
  raw_members="$tmp_dir/$target.raw-members"
  gzip -dc "$archive" | pax -f - > "$raw_members"
  if ! reject_appledouble_members "$archive" "$raw_members"; then
    exit 1
  fi
  env COPYFILE_DISABLE=1 tar -tzf "$archive" > "$members"
  awk -v archive="$archive" -v name="$name" -v binary="$binary" '
    BEGIN {
      required[name "/"] = 1
      required[name "/README.md"] = 1
      required[name "/SECURITY.md"] = 1
      required[name "/VERSION"] = 1
      required[name "/" binary] = 1
      required[name "/docs/"] = 1
      required[name "/docs/technical-overview.md"] = 1
      required[name "/docs/roadmap.md"] = 1
      required[name "/docs/threat-model-and-limitations.md"] = 1
    }
    {
      member = $0
      seen[member]++
      if (!(member in required)) {
        print archive " contains unexpected archive member: " member > "/dev/stderr"
        failed = 1
      }
    }
    END {
      for (member in required) {
        if (seen[member] == 0) {
          print archive " is missing required archive member: " member > "/dev/stderr"
          failed = 1
        } else if (seen[member] != 1) {
          print archive " contains duplicate archive member: " member > "/dev/stderr"
          failed = 1
        }
      }
      exit failed
    }
  ' "$members"
  require_directory_member "$archive" "$name/"
  require_directory_member "$archive" "$name/docs/"
  require_regular_member "$archive" "$name/README.md"
  require_regular_member "$archive" "$name/SECURITY.md"
  require_regular_member "$archive" "$name/VERSION"
  require_regular_member "$archive" "$name/docs/technical-overview.md"
  require_regular_member "$archive" "$name/docs/roadmap.md"
  require_regular_member "$archive" "$name/docs/threat-model-and-limitations.md"
  readme="$tmp_dir/$target.readme"
  readme_links="$tmp_dir/$target.readme-links"
  tar -xOf "$archive" "$name/README.md" > "$readme"
  awk '
    {
      line = $0
      while (match(line, /\]\([^)]*\)/)) {
        link = substr(line, RSTART + 2, RLENGTH - 3)
        sub(/[[:space:]].*$/, "", link)
        sub(/#.*/, "", link)
        if (link != "" && link !~ /^[[:alpha:]][[:alnum:]+.-]*:/ && link !~ /^\//) {
          print link
        }
        line = substr(line, RSTART + RLENGTH)
      }
    }
  ' "$readme" | LC_ALL=C sort -u > "$readme_links"
  while IFS= read -r link; do
    case "$link" in
      .|..|/*|../*|*/../*|*/..)
        echo "$archive README.md contains unsafe local link: $link" >&2
        exit 1
        ;;
    esac
    require_readme_linked_member "$archive" "$name/$link"
  done < "$readme_links"
  archive_version="$tmp_dir/$target.version"
  expected_version="$tmp_dir/expected-version"
  tar -xOf "$archive" "$name/VERSION" > "$archive_version"
  printf '%s\n' "$version" > "$expected_version"
  if ! cmp -s "$archive_version" "$expected_version"; then
    echo "$archive VERSION must be exactly one normalized line equal to $version" >&2
    exit 1
  fi
  require_regular_member "$archive" "$name/$binary"
  case "$target" in
    windows_*) ;;
    *)
      mode="$(tar_member_mode "$archive" "$name/$binary")"
      owner_execute="$(printf '%s\n' "$mode" | awk '{print substr($0, 4, 1)}')"
      case "$owner_execute" in
        x|s) ;;
        *)
          echo "$archive $binary is not executable by its owner" >&2
          exit 1
          ;;
      esac
      ;;
  esac
done
