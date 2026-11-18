import sqlite3

def migrate():
    conn = sqlite3.connect('backend/phishguard.db')
    cur = conn.cursor()
    cur.execute('PRAGMA table_info(gmail_integrations)')
    existing = set(r[1] for r in cur.fetchall())

    cols_to_add = [
        ('connection_status', "VARCHAR(50) DEFAULT 'connected'"),
        ('token_status', "VARCHAR(50) DEFAULT 'valid'"),
        ('refresh_token_encrypted', 'BLOB'),
        ('access_token_encrypted', 'BLOB'),
        ('token_expires_at', 'DATETIME'),
        ('granted_scopes', 'JSON'),
        ('connected_at', 'DATETIME'),
        ('last_verified_at', 'DATETIME'),
        ('last_history_id', 'VARCHAR(64)'),
        ('quarantine_label_id', 'VARCHAR(100)'),
        ('quarantine_label_name', "VARCHAR(100) DEFAULT 'PhishGuard-Quarantine'"),
        ('auto_quarantine_enabled', 'BOOLEAN DEFAULT 0'),
        ('quarantine_consent_given_at', 'DATETIME'),
        ('quarantine_threshold_score', 'INTEGER DEFAULT 70'),
        ('watch_status', "VARCHAR(50) DEFAULT 'inactive'"),
        ('watch_expiration', 'DATETIME'),
        ('last_error', 'TEXT'),
    ]

    for col_name, col_def in cols_to_add:
        if col_name not in existing:
            print(f'Adding {col_name}...')
            cur.execute(f'ALTER TABLE gmail_integrations ADD COLUMN {col_name} {col_def}')
    conn.commit()
    print('Migration complete!')

if __name__ == '__main__':
    migrate()
