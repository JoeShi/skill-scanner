// @skill-scanner/github-action — populated by @Cody in v1 CI integration phase
// Wraps skillchk scan for use in GitHub Actions workflows with SARIF output
// for GitHub Code Scanning integration.
//
// Planned interface:
//   - inputs: target, fail-on, ruleset, format
//   - outputs: sarif-file, findings-count, blocked
//   - posts SARIF to GitHub Security tab via upload-sarif action
