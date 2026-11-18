import os
import sys
import sqlite3

# Ensure backend package is in path
sys.path.insert(0, os.path.abspath('backend'))

# Load .env
from dotenv import load_dotenv
load_dotenv('.env')

from app.core.database import Base
import app.models

def sync_schema(db_path):
    print(f"Checking schema for {db_path}...")
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    for table in Base.metadata.tables.values():
        cur.execute(f"PRAGMA table_info({table.name})")
        existing_cols = {r[1]: r for r in cur.fetchall()}
        
        for col in table.columns:
            if col.name not in existing_cols:
                col_type = str(col.type)
                # Map postgres types to sqlite types
                if "VARCHAR" in col_type or "STRING" in col_type or "TEXT" in col_type or "UUID" in col_type:
                    sql_type = "TEXT"
                elif "BOOLEAN" in col_type:
                    sql_type = "BOOLEAN"
                elif "INTEGER" in col_type:
                    sql_type = "INTEGER"
                elif "FLOAT" in col_type:
                    sql_type = "REAL"
                elif "DATETIME" in col_type or "TIMESTAMP" in col_type:
                    sql_type = "DATETIME"
                elif "BYTEA" in col_type or "BLOB" in col_type:
                    sql_type = "BLOB"
                elif "JSON" in col_type:
                    sql_type = "JSON"
                else:
                    sql_type = "TEXT"
                
                default_clause = ""
                if col.default is not None:
                    if hasattr(col.default, 'arg'):
                        arg = col.default.arg
                        if isinstance(arg, bool):
                            default_clause = f" DEFAULT {1 if arg else 0}"
                        elif isinstance(arg, (int, float)):
                            default_clause = f" DEFAULT {arg}"
                        elif isinstance(arg, str):
                            default_clause = f" DEFAULT '{arg}'"
                elif col.server_default is not None:
                    default_clause = ""

                alter_sql = f"ALTER TABLE {table.name} ADD COLUMN {col.name} {sql_type}{default_clause}"
                print(f"  [{table.name}] Executing: {alter_sql}")
                try:
                    cur.execute(alter_sql)
                except Exception as e:
                    print(f"  Error altering {table.name}.{col.name}: {e}")

    conn.commit()
    conn.close()
    print("Schema sync complete!")

if __name__ == "__main__":
    sync_schema('backend/phishguard.db')
    sync_schema('phishguard.db')
