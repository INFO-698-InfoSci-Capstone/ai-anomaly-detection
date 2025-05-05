import sqlite3

conn = sqlite3.connect("logs.db")
cursor = conn.cursor()

cursor.execute("""
    CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        source_ip TEXT,
        destination_ip TEXT,
        protocol TEXT,
        anomaly_score REAL,
        predicted_traffic_type TEXT,
        risk_flag TEXT,
        confidence_score REAL,  -- Add this column
        log_id TEXT UNIQUE
    )
""")

conn.commit()
conn.close()
print("Database initialized successfully.")