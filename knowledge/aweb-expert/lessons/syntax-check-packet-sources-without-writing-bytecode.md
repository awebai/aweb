---
type: Lesson
title: Syntax-check packet sources without writing bytecode
description: python -m py_compile writes __pycache__ beside the source whatever -B or PYTHONDONTWRITEBYTECODE say, so a syntax check can put unreviewed files into a staging tree; check packet sources with ast.parse instead.
tags: [lesson, packets, python, staging, hygiene]
timestamp: 2026-11-20
---

Writing the `.pyc` file is the whole job of `py_compile`. `-B` and
`PYTHONDONTWRITEBYTECODE` (or `sys.dont_write_bytecode`) stop only the import
system from writing bytecode, so a "syntax check" with
`python -m py_compile` leaves `__pycache__/` beside the sources it checked.
Where a staging tree must hold only reviewed files, as a release or deploy
packet does, that check adds files nobody reviewed. Stray `__pycache__`
directories were found beside packet sources after py_compile checks.

**What to do.** Syntax-check without writing anything:

```sh
python3 -I -B -c "import ast,sys; ast.parse(open(sys.argv[1]).read())" FILE
```

Never use `py_compile` or `compileall` on a staging tree.

**Elimination route.** A staging check that compares the tree with the
reviewed file list and refuses any extra file would catch this and every
similar stray. Where a packet has such a check, it is the real guard, and
this lesson only explains the failure it reports.

Evidence: OKF proposal from aweb-expert/aweb-expert-deploy-team, 2026-11-20;
notes/py-compile-writes-bytecode.md. Verified at harvest: `python3 -B -m
py_compile` with `PYTHONDONTWRITEBYTECODE=1` set still created
`__pycache__/`.
