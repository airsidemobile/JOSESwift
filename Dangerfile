fail "Please provide a summary in the Pull Request description" if github.pr_body.length < 5

warn("Work in Progress") if github.pr_title.include? "WIP"

swiftlint.config_file = '.swiftlint.yml'
swiftlint.lint_files inline_mode: true
