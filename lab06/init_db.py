# init_db.py
import sqlite3

def init_db(path="test.db"):
    conn = sqlite3.connect(path)
    cur = conn.cursor()

    cur.executescript("""
    DROP TABLE IF EXISTS users;
    DROP TABLE IF EXISTS products;

    CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT
    );

    CREATE TABLE products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        category TEXT,
        released INTEGER
    );
    """)

    users = [
        ("admin", "adminpass"),
        ("alice", "alicepass"),
        ("bob", "bobpass"),
    ]
    cur.executemany("INSERT INTO users(username, password) VALUES (?, ?);", users)

    products = [
        ("Red Backpack", "Gifts", 1),
        ("Secret Prototype", "Gifts", 0),  # unreleased
        ("Blue Shirt", "Apparel", 1),
        ("Hidden Notes", "Docs", 0),       # unreleased
    ]
    cur.executemany("INSERT INTO products(name, category, released) VALUES (?, ?, ?);", products)

    conn.commit()
    conn.close()
    print("DB initialized at", path)

if __name__ == "__main__":
    init_db()
