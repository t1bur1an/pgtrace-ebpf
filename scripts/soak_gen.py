#!/usr/bin/env python3
"""Generate pgbench scripts for the soak test into deploy/soak/gen/.

Stream "big" (simple protocol) sends statements with large JSON literals
(hundreds of KB) so the capture path sees messages far beyond the 4 KiB
per-syscall and 64 KiB parser caps, with multi-byte UTF-8 throughout.
Stream "ext" (prepared protocol) builds large JSON server-side and reads it
back, producing large result rows. Stream "churn" reconnects per transaction.
"""
import json
import os
import random

OUT = os.path.join(os.path.dirname(__file__), "..", "deploy", "soak", "gen")
os.makedirs(OUT, exist_ok=True)
rnd = random.Random(42)
WORDS = ["alpha", "бета", "гамма", "δέλτα", "数据", "库存", "🚀", "✓", "naïve", "façade", "zürich", "ÅÄÖ", "emoji😀"]


def text(n):
    return " ".join(rnd.choice(WORDS) for _ in range(n))


def doc(kb, kind):
    """A JSON document of roughly kb kilobytes. Values never contain ':' so
    pgbench can't mistake them for variable references."""
    d = {"kind": kind, "version": 3, "flags": {"active": True, "archived": False, "score": 0.75},
         "owner": {"name": text(3), "email": "user_at_example.org", "roles": ["reader", "writer"]},
         "items": []}
    i = 0
    while len(json.dumps(d, ensure_ascii=False).encode()) < kb * 1024:
        d["items"].append({"i": i, "sku": f"SKU-{i:06d}", "qty": rnd.randint(1, 99), "price": round(rnd.random() * 100, 2),
                           "note": text(rnd.randint(3, 12)), "attrs": {"color": rnd.choice(["red", "синий", "绿"]), "size": rnd.choice("SML")}})
        i += 1
    return json.dumps(d, ensure_ascii=False)  # default ", " / ": " separators keep ':' followed by a space


def lit(s):
    return "'" + s.replace("'", "''") + "'"


def write(name, body):
    with open(os.path.join(OUT, name), "w", encoding="utf-8") as f:
        f.write(body.strip() + "\n")


# --- stream "big": simple protocol, large literals ---------------------------
for v in range(4):
    rows = ",\n".join(
        f"(:t, {lit(doc(rnd.choice([20, 30, 45, 60]), 'k' + str(r % 10)))}::jsonb || jsonb_build_object('n', :n), "
        f"ARRAY['big','v{v}'], {lit(text(400))})"
        for r in range(10))
    write(f"big_insert_{v}.sql", f"""
\\set t random(1, 50)
\\set n random(1, 1000000000)
INSERT INTO soak_docs (tenant, payload, tags, body) VALUES
{rows};
""")
for v in range(3):
    write(f"big_replace_{v}.sql", f"""
\\set off random(0, 3000)
UPDATE soak_docs SET payload = {lit(doc(rnd.choice([40, 80, 120]), 'replaced'))}::jsonb, updated_at = now()
WHERE id = (SELECT max(id) - :off FROM soak_docs);
""")
write("big_delete.sql", """
\\set t random(1, 50)
DELETE FROM soak_docs WHERE id IN (SELECT id FROM soak_docs WHERE tenant = :t ORDER BY id LIMIT 300);
""")
write("big_txn.sql", f"""
\\set t random(1, 50)
\\set n random(1, 1000000000)
BEGIN;
INSERT INTO soak_docs (tenant, payload, body) VALUES (:t, {lit(doc(60, 'txn'))}::jsonb || jsonb_build_object('n', :n), {lit(text(2000))});
UPDATE soak_docs SET payload = jsonb_set(payload, '{{flags,score}}', to_jsonb(:n % 100)), updated_at = now()
  WHERE tenant = :t AND id > (SELECT max(id) - 3000 FROM soak_docs);
SELECT id, payload -> 'owner', jsonb_array_length(payload -> 'items') FROM soak_docs WHERE payload @> '{{"kind": "txn"}}' ORDER BY id DESC LIMIT 5;
COMMIT;
""")

# --- stream "ext": prepared protocol, server-built JSON, big result rows -----
write("ext_insert.sql", """
\\set t random(1, 50)
\\set rows random(5, 40)
\\set items random(10, 200)
\\set rep random(10, 300)
INSERT INTO soak_docs (tenant, payload, tags, body)
SELECT :t,
       jsonb_build_object('kind', 'k' || (g % 10), 'n', g, 'lang', 'рус', 'items',
         (SELECT jsonb_agg(jsonb_build_object('i', i, 'v', md5(i::text || g), 'u', 'ünïcødé 数据 🚀')) FROM generate_series(1, :items) i)),
       ARRAY['ext', 'gen'],
       repeat(md5(g::text), :rep)
FROM generate_series(1, :rows) g;
""")
write("ext_update.sql", """
\\set t random(1, 50)
\\set n random(1, 1000000000)
UPDATE soak_docs SET payload = jsonb_set(payload, '{n}', to_jsonb(:n::bigint)), body = left(body, 2000) || md5(:n::text), updated_at = now()
WHERE tenant = :t AND id > (SELECT max(id) - 2000 FROM soak_docs);
""")
write("ext_select.sql", """
\\set k random(0, 9)
SELECT id, payload, body FROM soak_docs WHERE payload @> jsonb_build_object('kind', 'k' || :k) ORDER BY id DESC LIMIT 20;
""")
write("ext_jsonpath.sql", """
\\set t random(1, 50)
SELECT count(*), max(jsonb_array_length(payload -> 'items')) FROM soak_docs
WHERE tenant = :t AND payload @? '$.items[*] ? (@.i > 150)';
""")
write("ext_delete.sql", """
\\set t random(1, 50)
DELETE FROM soak_docs WHERE tenant = :t AND id < (SELECT max(id) - 15000 FROM soak_docs);
""")

# --- stream "churn": new connection per transaction ---------------------------
write("churn.sql", """
\\set t random(1, 50)
SELECT count(*) FROM soak_docs WHERE tenant = :t;
INSERT INTO soak_docs (tenant, payload) VALUES (:t, jsonb_build_object('kind', 'churn', 'at', now()));
""")

sizes = {f: os.path.getsize(os.path.join(OUT, f)) for f in sorted(os.listdir(OUT))}
for f, n in sizes.items():
    print(f"{f:22s} {n / 1024:8.1f} KiB")
