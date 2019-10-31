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

# ------------------------------------------------------------------------------
# Dependency check
# ------------------------------------------------------------------------------

dependency_report_file = "./dependency-check-report.json"
if File.exist?(dependency_report_file)
  require "json"

  file = File.read(dependency_report_file)
  json = JSON.parse(file)

  vulnerable_dependency_exists = false
  vulnerable_dependencies = "## Vulnerable dependencies\n"

  json['dependencies'].each do |dependency|
    if dependency.key?('vulnerabilities')
      vulnerable_dependency_exists = true
      vulnerable_dependencies = vulnerable_dependencies + "- #{dependency['fileName']}\n"
    end
  end

  if vulnerable_dependency_exists
    fail(vulnerable_dependencies)
  else
    message("No vulnerable dependencies.")
  end
end