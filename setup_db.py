import sqlite3

conn = sqlite3.connect("files.db")
cur = conn.cursor()

# Drop the old table if it exists (to avoid schema mismatch)
cur.execute("DROP TABLE IF EXISTS files")

# Create the correct table matching your app.py
cur.execute("""
CREATE TABLE files (
    id TEXT PRIMARY KEY,
    original_name TEXT NOT NULL,
    storage_path TEXT NOT NULL,
    nonce TEXT NOT NULL,
    tag TEXT NOT NULL,
    size INTEGER NOT NULL
)
""")

conn.commit()
conn.close()

print("✅ Database and correct 'files' table created successfully!")
