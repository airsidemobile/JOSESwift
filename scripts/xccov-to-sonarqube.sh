#!/usr/bin/env bash
set -euo pipefail

# Adapted from
# https://docs.sonarqube.org/display/PLUG/Swift+Coverage+Results+Import
# https://github.com/SonarSource/sonar-scanning-examples/blob/master/swift-coverage/swift-coverage-example/xccov-to-sonarqube-generic.sh

function convert_file {
  local xcresult_bundle="$1"
  local file_name="$2"
  echo "  <file path=\"$file_name\">"
  xcrun xccov view --archive --file "$file_name" "$xcresult_bundle" | \
    sed -n '
    s/^ *\([0-9][0-9]*\): 0.*$/    <lineToCover lineNumber="\1" covered="false"\/>/p;
    s/^ *\([0-9][0-9]*\): [1-9].*$/    <lineToCover lineNumber="\1" covered="true"\/>/p
    '
  echo '  </file>'
}

function xccov_to_generic {
  echo '<coverage version="1">'
  for xcresult_bundle in "$@"; do
    xcrun xccov view --archive --file-list "$xcresult_bundle" | while read -r file_name; do
      convert_file "$xcresult_bundle" "$file_name"
    done
  done
  echo '</coverage>'
}

xccov_to_generic "$@"
