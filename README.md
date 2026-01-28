# Parallax

Code review through multiple lenses. Same diff, different concerns.

## The Problem

Code review is cognitively overloaded. Security, performance, maintainability, testing - you're supposed to check everything at once. Nobody can. So issues slip through not because reviewers are negligent, but because human attention has limits.

## The Solution

Parallax analyzes your diffs through specialized lenses. Each lens focuses on one concern and surfaces relevant findings. Click through Security, Performance, Maintainability - see the same code, different annotations.

## Features

- **Security Lens** - SQL injection, XSS, command injection, path traversal, hardcoded secrets, weak crypto
- **Maintainability Lens** - Complexity, function length, parameter count, deep nesting, magic numbers
- **Testing Lens** - Missing tests, weak assertions, flaky patterns
- **Multiple output formats** - Text, JSON, SARIF, Markdown
- **Inline suppression** - Silence specific warnings with comments
- **Git integration** - Analyze commits, ranges, and PRs

## Quick Start

```bash
pip install parallax

# Analyze a diff file
parallax analyze changes.patch

# Analyze uncommitted changes
parallax analyze .

# Analyze a specific commit
parallax analyze --commit abc123

# Analyze a commit range
parallax analyze --range main..feature-branch

# Analyze a GitHub PR
parallax analyze --pr https://github.com/owner/repo/pull/123

# Output as JSON
parallax analyze changes.patch -o json

# Run specific lenses only
parallax analyze changes.patch -l security -l maintainability
```

## Configuration

Create `.parallax.yaml` in your project:

```yaml
lenses:
  security:
    enabled: true
  maintainability:
    rules:
      cyclomatic_complexity:
        threshold: 15
      function_length:
        max_lines: 100

settings:
  min_confidence: 0.5
  fail_on: high

ignore:
  paths:
    - "**/test_*.py"
```

## Inline Suppression

Silence specific findings with comments:

```python
# Same line - suppress finding on this line
cursor.execute(f"SELECT * FROM {table}")  # parallax-ignore security/sql-injection

# Next line - suppress finding on the following line
# parallax-ignore-next-line maintainability/complexity
def complex_function():
    ...

# File level - suppress all matching findings in this file
# parallax-ignore-file testing/*
```

Wildcards work: `security/*` suppresses all security rules, `*/*` suppresses everything.

## License

MIT

## Author

Katie the Clawdius Prime

---

*The second pair of eyes that never gets tired and knows something about everything.*
