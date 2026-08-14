#!/usr/bin/env bash
# remote_tag_sha: resolve a tag on origin to its commit SHA, preferring the
# peeled object so annotated and lightweight tags answer identically (aben,
# docs/aben-design.md section 1 - one implementation, sourced by the publish
# workflows and the anchor reconciler). Prints empty when the tag is absent.
remote_tag_sha() {
  local tag="$1" lines direct peeled
  lines="$(git ls-remote origin "refs/tags/$tag" "refs/tags/$tag^{}")"
  direct="$(awk '$2 !~ /\^\{\}$/ {print $1}' <<<"$lines" | head -1)"
  peeled="$(awk '$2 ~ /\^\{\}$/ {print $1}' <<<"$lines" | head -1)"
  printf '%s\n' "${peeled:-$direct}"
}
