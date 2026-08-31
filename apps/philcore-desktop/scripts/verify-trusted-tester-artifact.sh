#!/bin/bash
set -euo pipefail

if [[ $# -ne 4 ]]; then
  echo "usage: verify-trusted-tester-artifact.sh ZIP EXPECTED_SHA256 EXPECTED_AUTHORITY EXPECTED_TEAM_ID" >&2
  exit 64
fi
artifact=$1
expected_sha=$2
expected_authority=$3
expected_team=$4
verify_mode=${PHILCORE_TRUSTED_TESTER_VERIFY_MODE:-final}
case "$verify_mode" in
  final|preupload) ;;
  *) echo "unsupported_verification_mode:$verify_mode" >&2; exit 64 ;;
esac
[[ -f "$artifact" ]] || { echo "artifact_missing" >&2; exit 65; }
actual_sha=$(/usr/bin/shasum -a 256 "$artifact" | /usr/bin/awk '{print $1}')
[[ "$actual_sha" == "$expected_sha" ]] || { echo "checksum_failure" >&2; exit 66; }

verify_root=$(/usr/bin/mktemp -d)
trap '/bin/rm -rf "$verify_root"' EXIT
entry_list="$verify_root/archive-entries.txt"
/usr/bin/zipinfo -1 "$artifact" > "$entry_list" || { echo "archive_inspection_failure" >&2; exit 75; }
if /usr/bin/awk '
  BEGIN { failed=0 }
  {
    count=split($0, part, "/");
    for (i=1; i<=count; i++) {
      if (part[i] ~ /^\._/) { print "appledouble:" $0; failed=1; exit }
      if (part[i] == ".DS_Store") { print "finder_metadata:" $0; failed=1; exit }
      if (part[i] == "__MACOSX") { print "macos_metadata_directory:" $0; failed=1; exit }
    }
  }
  END { exit failed }
' "$entry_list" >&2; then :; else echo "archive_contamination" >&2; exit 76; fi

/usr/bin/ditto -x -k --norsrc "$artifact" "$verify_root"
app=$(find "$verify_root" -maxdepth 1 -name '*.app' -type d -print -quit)
[[ -n "$app" ]] || { echo "application_missing" >&2; exit 67; }
if find "$app" \( -name '._*' -o -name '.DS_Store' -o -name '__MACOSX' \) -print -quit | grep . >/dev/null; then
  echo "extraction_contamination" >&2
  exit 77
fi

framework="$app/Contents/Frameworks/Electron Framework.framework"
[[ -d "$framework/Versions" ]] || { echo "framework_layout_failure:Versions" >&2; exit 78; }
for entry in "$framework"/* "$framework"/.[!.]*; do
  [[ -e "$entry" || -L "$entry" ]] || continue
  name=${entry##*/}
  case "$name" in
    "Electron Framework"|Helpers|Libraries|Resources|Versions) ;;
    *) echo "framework_layout_failure:unexpected_root_entry:$name" >&2; exit 78 ;;
  esac
done
while IFS='|' read -r name expected; do
  link="$framework/$name"
  [[ -L "$link" ]] || { echo "framework_symlink_failure:not_symlink:$name" >&2; exit 79; }
  actual=$(/usr/bin/readlink "$link")
  [[ "$actual" == "$expected" ]] || { echo "framework_symlink_failure:$name:$actual" >&2; exit 79; }
  [[ -e "$link" ]] || { echo "framework_symlink_failure:broken:$name" >&2; exit 79; }
done <<'SYMLINKS'
Electron Framework|Versions/Current/Electron Framework
Helpers|Versions/Current/Helpers
Libraries|Versions/Current/Libraries
Resources|Versions/Current/Resources
SYMLINKS
while IFS= read -r -d '' link; do
  target=$(/usr/bin/readlink "$link")
  [[ "$target" != /* ]] || { echo "symlink_failure:absolute:$link" >&2; exit 80; }
  [[ -e "$link" ]] || { echo "symlink_failure:broken:$link" >&2; exit 80; }
done < <(find "$app" -type l -print0)
/usr/bin/codesign --verify --deep --strict --verbose=4 "$app" || { echo "signature_failure" >&2; exit 68; }
details=$(/usr/bin/codesign -dvvv "$app" 2>&1)
grep -F "Authority=$expected_authority" <<<"$details" >/dev/null || { echo "authority_failure" >&2; exit 69; }
grep -F "TeamIdentifier=$expected_team" <<<"$details" >/dev/null || { echo "team_id_failure" >&2; exit 70; }
if [[ "$verify_mode" == "final" ]]; then
  /usr/bin/xcrun stapler validate "$app" || { echo "staple_failure" >&2; exit 71; }
  /usr/sbin/spctl --assess --type execute --verbose=4 "$app" || { echo "gatekeeper_failure" >&2; exit 72; }
  staple_validation_passed=true
  gatekeeper_assessment_passed=true
  gatekeeper_preupload_unnotarized_rejection_observed=false
else
  if /usr/bin/xcrun stapler validate "$app" >/tmp/philcore-preupload-stapler.log 2>&1; then
    echo "preupload_unexpected_staple" >&2
    exit 71
  fi
  gatekeeper_output=$(/usr/sbin/spctl --assess --type execute --verbose=4 "$app" 2>&1) && {
    echo "preupload_unexpected_gatekeeper_acceptance" >&2
    exit 72
  }
  grep -F "Unnotarized Developer ID" <<<"$gatekeeper_output" >/dev/null || {
    echo "preupload_gatekeeper_rejection_unexpected" >&2
    exit 72
  }
  staple_validation_passed=false
  gatekeeper_assessment_passed=false
  gatekeeper_preupload_unnotarized_rejection_observed=true
fi

manifest="$app/Contents/Resources/app/config/release/philcore-desktop-local-alpha.json"
[[ -f "$manifest" ]] || { echo "release_manifest_missing" >&2; exit 73; }
for component in prover verifier userPresenceHelper; do
  expected=$(/usr/bin/plutil -extract "bundledResources.$component.sha256" raw "$manifest")
  component_path=$(/usr/bin/plutil -extract "bundledResources.$component.path" raw "$manifest")
  component_file="$app/Contents/Resources/app/${component_path#*Contents/Resources/app/}"
  actual=$(/usr/bin/shasum -a 256 "$component_file" | /usr/bin/awk '{print $1}')
  [[ "$actual" == "$expected" ]] || { echo "internal_component_hash_failure:$component" >&2; exit 74; }
done
inventory_sha=$(
  cd "$app"
  find . -print | LC_ALL=C sort | while IFS= read -r item; do
    mode=$(/usr/bin/stat -f '%Sp:%z' "$item" 2>/dev/null || /usr/bin/stat -f '%Sp:0' "$item")
    if [[ -L "$item" ]]; then printf '%s|%s|%s\n' "$item" "$mode" "$(/usr/bin/readlink "$item")"
    else printf '%s|%s\n' "$item" "$mode"
    fi
  done | /usr/bin/shasum -a 256 | /usr/bin/awk '{print $1}'
)
cat <<EVIDENCE
verification_evidence:
mode=$verify_mode
zip_sha256=$actual_sha
extraction_mechanism=ditto -x -k --norsrc
extraction_directory=$verify_root
current_macos_user=$(/usr/bin/id -un)
extracted_app_inventory_sha256=$inventory_sha
archive_appledouble_found=false
extracted_appledouble_found=false
users_shared_transfer_exercised=false
finder_extraction_performed=false
finder_launch_performed=false
strict_codesign_passed=true
staple_validation_passed=$staple_validation_passed
gatekeeper_assessment_passed=$gatekeeper_assessment_passed
gatekeeper_preupload_unnotarized_rejection_observed=$gatekeeper_preupload_unnotarized_rejection_observed
authority_verified=true
team_id_verified=true
internal_component_hashes_verified=true
EVIDENCE
if [[ "$verify_mode" == "final" ]]; then
  echo "trusted_tester_artifact_verified"
else
  echo "trusted_tester_preupload_artifact_verified"
fi
