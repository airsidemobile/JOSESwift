# ------------------------------------------------------------------------------
# Say thanks!
# ------------------------------------------------------------------------------

unless github.api.organization_member?('airsidemobile', github.pr_author)
  message "Thanks for your contribution @#{github.pr_author}! :tada: You'll hear back from us soon."
end

# ------------------------------------------------------------------------------
# Do you have style?
# ------------------------------------------------------------------------------

swiftlint.config_file = '.swiftlint.yml'

has_linting_violations = false
swiftlint.lint_files(inline_mode: true, fail_on_error: true) { |violation|
	has_linting_violations = true
}

if has_linting_violations 
	warn("Your pull request seems to introduce linting violations. Some of them may be fixable by running `bundle exec fastlane format_code`.")
end

# ------------------------------------------------------------------------------
# Did you add a changelog entry?
# ------------------------------------------------------------------------------

has_changes = !git.modified_files.grep(/Sources/).empty? || !git.modified_files.grep(/Tests/).empty?
no_changelog_entry = !git.modified_files.include?("Changelog.md")
not_declared_trivial = !(github.pr_labels.include? "trivial")

if has_changes && no_changelog_entry && not_declared_trivial
  message("Any non-trivial changes to code should be reflected in the changelog. Please consider adding a note in the _Unreleased_ section of the [CHANGELOG.md](https://github.com/airsidemobile/JOSESwift/blob/master/CHANGELOG.md).")
end
