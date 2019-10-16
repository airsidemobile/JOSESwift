#!/bin/sh

current_license_header="Copyright $(date +%Y) Airside Mobile Inc."
any_license_header="Copyright [0-9]* Airside Mobile Inc."

find JOSESwift/Sources Tests -name "*.swift" \
	| xargs grep -lv "$current_license_header" \
	| xargs sed -i '' "s/$any_license_header/$current_license_header/"
