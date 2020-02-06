import Danger

let danger = Danger()

// -----------------------------------------------------------------------------
// Did you add a changelog entry?
// -----------------------------------------------------------------------------

let hasChangelog = danger.git.modifiedFiles.contains("CHANGELOG.md")
let isTrivial = danger.github.pullRequest.labels.contains("trivial")

if !hasChangelog && !isTrivial {
	warn("Any non-trivial changes to code should be reflected in the changelog. Please consider adding a note in the _Unreleased_ section of the [CHANGELOG.md](https://github.com/airsidemobile/JOSESwift/blob/master/CHANGELOG.md).")
}


// # ------------------------------------------------------------------------------
// # Do you have style?
// # ------------------------------------------------------------------------------

// swiftlint.config_file = '.swiftlint.yml'

// has_linting_violations = false
// swiftlint.lint_files(inline_mode: true, fail_on_error: true) { |violation|
// 	has_linting_violations = true
// }

// if has_linting_violations 
// 	warn("Your pull request seems to introduce linting violations. Some of them may be fixable by running `bundle exec fastlane format_code`.")
// end
