"""Signal definitions, one module per pillar.

Each module exports ``SPECS: list[SignalSpec]``. :mod:`app.entra.signals` concatenates them
and validates that ids are unique and pillars are known.
"""
