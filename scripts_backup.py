"""Consistent online backup of the SQLite database. Run: python scripts_backup.py [target.db]"""
import sqlite3, sys, time, os
src = os.environ.get("DB_PATH", "aicte_svp_v2.db")
dst = sys.argv[1] if len(sys.argv) > 1 else f"backup-{time.strftime('%Y%m%d-%H%M%S')}.db"
a, b = sqlite3.connect(src), sqlite3.connect(dst)
a.backup(b); b.close(); a.close()
print("Backup written to", dst)
