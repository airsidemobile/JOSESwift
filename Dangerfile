# # ------------------------------------------------------------------------------
# # Are the basics ok?
# # ------------------------------------------------------------------------------

# if github.pr_body.length < 5
#   fail "Please provide a summary in the Pull Request description"
# end

# changelog.have_you_updated_changelog?

# # ------------------------------------------------------------------------------
# # Do modified files have a high enough code coverage?
# # ------------------------------------------------------------------------------

# slather.configure("JOSESwift.xcodeproj", "JOSESwift", options: {
#   workspace: 'JOSESwift.xcworkspace'
# })

# slather.notify_if_modified_file_is_less_than(minimum_coverage: 80)

# # ------------------------------------------------------------------------------
# # Do you have style?
# # ------------------------------------------------------------------------------

swiftlint.lint_all_files = true
swiftlint.lint_files
