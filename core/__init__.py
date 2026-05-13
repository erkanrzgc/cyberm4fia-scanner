"""cyberm4fia-scanner — core package.

This package is intentionally minimal at the top level. Public surface
lives in its sub-packages:

  - ``core.module_registry``    — ``PHASE_MODULES``, ``ASYNC_MODULES``, URL helpers
  - ``core.module_runners``     — ``_run_*`` phase runner functions
  - ``core.scan_option_specs``  — argument / mode / profile / prompt specs
  - ``core.scan_options``       — CLI / API option builders
  - ``core.scan_context``       — per-target runtime state
  - ``core.session``            — session JSON persistence
  - ``core.engine``             — high-level scan orchestrator
  - ``core.output``             — terminal banners + finding formatters

Import from those sub-packages directly rather than from ``core``.
"""

__all__: list[str] = []
