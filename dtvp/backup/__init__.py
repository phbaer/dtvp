"""The instance dump ``dtvp.dump/1``: backup, restore and migration.

See docs/backup-and-restore.md for the format and the commands, and
docs/adr/0005-logical-dump-format.md for the decision. This package must not
import ``dtvp.main``, ``dtvp.dt_cache``, ``dtvp.boot`` or ``dtvp.app_wiring``:
those open the databases of the running instance.
"""
