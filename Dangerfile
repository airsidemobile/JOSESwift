# ------------------------------------------------------------------------------
# Do you have style?
# ------------------------------------------------------------------------------

swiftlint.config_file = '.swiftlint.yml'
swiftlint.lint_files inline_mode: true

# ------------------------------------------------------------------------------
# Did you add a changelog entry?
# ------------------------------------------------------------------------------

has_app_changes = !git.modified_files.grep(/Sources/).empty? || !git.modified_files.grep(/Tests/).empty?
no_changelog_entry = !git.modified_files.include?("Changelog.md")
not_declared_trivial = !(github.pr_labels.include? "trivial")

if has_app_changes && no_changelog_entry && not_declared_trivial
  warn("Any changes to library code should be reflected in the changelog. Please consider adding a note in the _Unreleased_ section of the [CHANGELOG.md](https://github.com/airsidemobile/JOSESwift/blob/master/CHANGELOG.md).")
end
