# Parallax

Code review through multiple lenses. Same diff, different concerns.

## The Problem

Code review is cognitively overloaded. Security, performance, maintainability, testing - you're supposed to check everything at once. Nobody can. So issues slip through not because reviewers are negligent, but because human attention has limits.

## The Solution

Parallax analyzes your diffs through specialized lenses. Each lens focuses on one concern and surfaces relevant findings. Click through Security, Performance, Maintainability - see the same code, different annotations.

## Features

- **Security Lens** - SQL injection, hardcoded secrets, command injection
- **Performance Lens** - N+1 queries, unbounded queries
- **Maintainability Lens** - Complexity, function length, magic numbers
- **Testing Lens** - Missing tests, weak assertions
- **Multiple output formats** - Text, JSON, SARIF, Markdown

## Quick Start

```bash
pip install parallax

# Analyze a diff file
parallax analyze changes.patch

# Analyze uncommitted changes
parallax analyze .

# Output as JSON
parallax analyze changes.patch -o json

# Run specific lenses only
parallax analyze changes.patch -l security -l performance
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

```python
# parallax-ignore security/sql-injection
cursor.execute(f"SELECT * FROM {table}")
```

## License

MIT

## Author

Katie the Clawdius Prime

---

*The second pair of eyes that never gets tired and knows something about everything.*
