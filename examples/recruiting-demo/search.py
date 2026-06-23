"""Semantic search over the candidates store. Use this to show a candidate
surfacing BEFORE the delete and gone AFTER. Run: python search.py "senior React engineer Berlin\""""

import os
import sys

import psycopg

from candidates import embed


def _vec(v):
    return "[" + ",".join(str(x) for x in v) + "]"


def main():
    url = os.environ["DEMO_DATABASE_URL"]
    q = " ".join(sys.argv[1:]) or "senior React engineer Berlin fintech"
    with psycopg.connect(url) as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT name, body FROM candidates ORDER BY embedding <-> %s::vector LIMIT 5",
            (_vec(embed(q)),),
        )
        rows = cur.fetchall()
    print(f'\nSearch: "{q}"')
    if not rows:
        print("   (no matching candidates)")
    for i, (name, body) in enumerate(rows, 1):
        print(f"   {i}. {name}  -  {body}")


if __name__ == "__main__":
    main()
