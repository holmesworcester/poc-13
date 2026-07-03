# poc-13

The atom model (poc-12 `docs/DESIGN.md`) as a minimal Python skeleton:
a single-file kernel plus a `facts/` tree in the poc-10 style.

- `kernel.py` — identity, admission, matching, and the turn loop. Nothing
  else: sync, hydration, retention, queues, effects, clocks, and content are
  fact families, not engine primitives, and live outside this file.
- `facts/` — one directory per scope, one module per fact family
  (constructor + `extract` + `project`). Projectors **are** the routers:
  `facts.ROOT` is a projector that dispatches on type-tag segments, and the
  kernel runs it like any other. `facts/__init__.py` is the table of contents.
- `tests/test_skeleton.py` — high-level tests of the headline claims:
  content-addressed idempotent admission, strict decode, cross-time
  suppression, watch-driven queues, and order-independent replay.

Run: `python3 tests/test_skeleton.py` (or `pytest`). No dependencies.
