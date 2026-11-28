import sqlite3

class UserRepository:
    """
    Data access layer. Receives the username from the Flask route.
    SINK: constructs a SQL query by string formatting — no parameterization.
    From this file alone, 'name' looks like an ordinary string parameter.
    Only cross-file taint analysis reveals it came from request.args.
    """

    def find_by_name(self, name):
        conn = sqlite3.connect("app.db")
        cursor = conn.cursor()

        # SINK: f-string interpolation of user-controlled input into SQL
        query = f"SELECT * FROM users WHERE username = '{name}'"
        cursor.execute(query)

        row = cursor.fetchone()
        conn.close()
        return str(row) if row else None
