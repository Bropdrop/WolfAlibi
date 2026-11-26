"""Independent read-only view of the separately stored latest reservation."""

import json, sqlite3, sys
from contextlib import closing
from research.sovereign.roles import serve


def head(request):
    if request != "head":
        raise ValueError("unsupported operation")
    with closing(
        sqlite3.connect("file:/store/reservations.sqlite3?mode=ro", uri=True)
    ) as c:
        return json.loads(
            c.execute(
                "SELECT record FROM reservations ORDER BY version DESC LIMIT 1"
            ).fetchone()[0]
        )


if __name__ == "__main__":
    serve("witness observation", head, sys.argv[1])
