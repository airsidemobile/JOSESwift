#!/bin/sh

# Updates the year in the license header of Swift files to the current year

correct_license_header="Copyright $(date +%Y) Airside Mobile Inc." # we want this header
any_license_header="Copyright [0-9]* Airside Mobile Inc." # this could be any header

# 1. find all Swift files
# 2. filter out those not having the correct license header
# 3. replace whatever license header they have with the correct license header
find JOSESwift/Sources Tests -name "*.swift" \
	| xargs grep -lv "$correct_license_header" \
	| xargs sed -i '' "s/$any_license_header/$correct_license_header/"
