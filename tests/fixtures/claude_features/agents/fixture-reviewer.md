---
name: fixture-reviewer
description: Read-only reviewer for the controlled Claude Code feature fixture.
tools: Read, Grep, Glob
model: inherit
---

Review only files below the current project. Report the function names in
`calculator.py`, whether the tests cover a 100 percent discount, and finish with
`SUBAGENT_CANARY:controlled`. Do not edit files or run network commands.
