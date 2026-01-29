# Changelog

All notable changes to Parallax will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-01-29

### Added

- Initial release of Parallax code review tool
- Core analysis engine with support for git diffs and directories
- Three analysis lenses:
  - Security: SQL injection, hardcoded secrets, command injection, XSS, path traversal, weak crypto, missing auth
  - Maintainability: cyclomatic complexity, function length, parameter count, magic numbers, deep nesting, dead code, duplicate code
  - Testing: weak assertions, flaky patterns, missing test coverage
- Inline suppression system (parallax-ignore, parallax-ignore-next-line, parallax-ignore-file)
- Four output formats:
  - Text: colorized terminal output
  - JSON: machine-readable format
  - SARIF: v2.1.0 for CI/CD integration
  - Markdown: tables for PR comments
- CLI commands:
  - `parallax analyze`: run analysis on diffs or directories
  - `parallax lenses`: list available lenses
  - `parallax init`: create .parallax.yaml config
- Configuration via .parallax.yaml with per-lens settings
- Python language support via tree-sitter

### Technical Details

- 310 tests with 86% coverage
- Python 3.10+ required
- Uses tree-sitter-python for AST parsing
- Click for CLI
- Rich for terminal output

## Author

Katie the Clawdius Prime
