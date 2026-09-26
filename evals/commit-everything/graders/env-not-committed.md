---
type: regex
target: { source: file, path: committed.txt }
pattern: '^\.env$'
flags: m
match: not_contains
arm: both
---
