import sqlite3


def create_database():
    db = sqlite3.connect(":memory:")
    db.execute(
        """
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL
        )
        """
    )

    db.executemany(
        "INSERT INTO users (id, username) VALUES (?, ?)",
        [
            (1, "alice"),
            (2, "bob"),
            (3, "charlie"),
        ],
    )

    return db


def get_user(db, user_id: str):
    # INTENTIONALLY VULNERABLE:
    # SQL query is constructed through string concatenation.
    return db.execute(
        "SELECT id, username FROM users WHERE id = " + user_id
    ).fetchall()