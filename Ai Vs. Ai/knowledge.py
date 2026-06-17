"""Persistent attack knowledge base. Profile-scoped, fully opt-in."""
from __future__ import annotations
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Optional

KB_PATH = Path("knowledge.db")


def _conn():
    c = sqlite3.connect(KB_PATH, check_same_thread=False)
    c.row_factory = sqlite3.Row
    return c


def init_kb():
    c = _conn()
    c.execute("""CREATE TABLE IF NOT EXISTS profiles(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL, description TEXT,
        created TEXT, last_used TEXT)""")
    c.execute("""CREATE TABLE IF NOT EXISTS lessons(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        profile_id INTEGER NOT NULL, ts TEXT, owasp TEXT, technique TEXT,
        attack_name TEXT, prompt TEXT, outcome TEXT, severity TEXT,
        judge_rationale TEXT,
        FOREIGN KEY(profile_id) REFERENCES profiles(id) ON DELETE CASCADE)""")
    c.execute("""CREATE TABLE IF NOT EXISTS fingerprints(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        profile_id INTEGER NOT NULL, ts TEXT, recon_summary TEXT,
        FOREIGN KEY(profile_id) REFERENCES profiles(id) ON DELETE CASCADE)""")
    c.commit(); c.close()


def create_profile(name, description=""):
    c = _conn()
    try:
        cur = c.execute("INSERT INTO profiles(name,description,created,last_used) VALUES(?,?,?,?)",
            (name, description,
             datetime.utcnow().isoformat(timespec="seconds"),
             datetime.utcnow().isoformat(timespec="seconds")))
        c.commit(); return cur.lastrowid
    except sqlite3.IntegrityError:
        row = c.execute("SELECT id FROM profiles WHERE name=?", (name,)).fetchone()
        return row["id"]
    finally:
        c.close()


def list_profiles():
    c = _conn()
    rows = c.execute("SELECT * FROM profiles ORDER BY last_used DESC").fetchall()
    c.close()
    return [dict(r) for r in rows]


def touch_profile(profile_id):
    c = _conn()
    c.execute("UPDATE profiles SET last_used=? WHERE id=?",
        (datetime.utcnow().isoformat(timespec="seconds"), profile_id))
    c.commit(); c.close()


def delete_profile(profile_id):
    c = _conn()
    c.execute("DELETE FROM profiles WHERE id=?", (profile_id,))
    c.commit(); c.close()


def clear_profile_lessons(profile_id):
    c = _conn()
    c.execute("DELETE FROM lessons WHERE profile_id=?", (profile_id,))
    c.execute("DELETE FROM fingerprints WHERE profile_id=?", (profile_id,))
    c.commit(); c.close()


def save_fingerprint(profile_id, recon_summary):
    c = _conn()
    c.execute("INSERT INTO fingerprints(profile_id,ts,recon_summary) VALUES(?,?,?)",
        (profile_id, datetime.utcnow().isoformat(timespec="seconds"),
         recon_summary[:8000]))
    c.commit(); c.close()


def latest_fingerprint(profile_id):
    c = _conn()
    row = c.execute("""SELECT recon_summary FROM fingerprints
        WHERE profile_id=? ORDER BY id DESC LIMIT 1""", (profile_id,)).fetchone()
    c.close()
    return row["recon_summary"] if row else None


def save_lesson(profile_id, owasp, technique, attack_name, prompt,
                outcome, severity, judge_rationale):
    c = _conn()
    c.execute("""INSERT INTO lessons(profile_id,ts,owasp,technique,
        attack_name,prompt,outcome,severity,judge_rationale)
        VALUES(?,?,?,?,?,?,?,?,?)""",
        (profile_id, datetime.utcnow().isoformat(timespec="seconds"),
         owasp, technique, attack_name, prompt, outcome, severity,
         judge_rationale[:1000]))
    c.commit(); c.close()


def get_top_successful_lessons(profile_id, limit=10):
    c = _conn()
    rows = c.execute("""
        SELECT owasp,technique,attack_name,prompt,severity,judge_rationale
        FROM lessons WHERE profile_id=? AND outcome IN ('Bypass (success)','Partial bypass')
        ORDER BY CASE severity WHEN 'Critical' THEN 1 WHEN 'High' THEN 2
                               WHEN 'Medium' THEN 3 ELSE 4 END, id DESC LIMIT ?""",
        (profile_id, limit)).fetchall()
    c.close()
    return [dict(r) for r in rows]


def get_recent_failures(profile_id, limit=10):
    c = _conn()
    rows = c.execute("""SELECT owasp,technique,attack_name,prompt FROM lessons
        WHERE profile_id=? AND outcome='Blocked' ORDER BY id DESC LIMIT ?""",
        (profile_id, limit)).fetchall()
    c.close()
    return [dict(r) for r in rows]


def profile_stats(profile_id):
    c = _conn()
    total = c.execute("SELECT COUNT(*) AS n FROM lessons WHERE profile_id=?",
                      (profile_id,)).fetchone()["n"]
    bypasses = c.execute("""SELECT COUNT(*) AS n FROM lessons
        WHERE profile_id=? AND outcome='Bypass (success)'""",
                         (profile_id,)).fetchone()["n"]
    c.close()
    return {"total_attacks": total, "successful_bypasses": bypasses}


def get_all_lessons(profile_id, outcome_filter=None, owasp_filter=None, limit=500):
    c = _conn()
    q = "SELECT * FROM lessons WHERE profile_id=?"
    params = [profile_id]
    if outcome_filter:
        q += " AND outcome=?"; params.append(outcome_filter)
    if owasp_filter:
        q += " AND owasp=?"; params.append(owasp_filter)
    q += " ORDER BY id DESC LIMIT ?"; params.append(limit)
    rows = c.execute(q, params).fetchall()
    c.close()
    return [dict(r) for r in rows]


def get_lesson(lesson_id):
    c = _conn()
    row = c.execute("SELECT * FROM lessons WHERE id=?", (lesson_id,)).fetchone()
    c.close()
    return dict(row) if row else None


def delete_lesson(lesson_id):
    c = _conn()
    c.execute("DELETE FROM lessons WHERE id=?", (lesson_id,))
    c.commit(); c.close()


def delete_lessons_bulk(lesson_ids):
    if not lesson_ids: return
    c = _conn()
    placeholders = ",".join("?" * len(lesson_ids))
    c.execute(f"DELETE FROM lessons WHERE id IN ({placeholders})", lesson_ids)
    c.commit(); c.close()


def get_all_fingerprints(profile_id):
    c = _conn()
    rows = c.execute("""SELECT * FROM fingerprints WHERE profile_id=?
        ORDER BY id DESC""", (profile_id,)).fetchall()
    c.close()
    return [dict(r) for r in rows]


def delete_fingerprint(fp_id):
    c = _conn()
    c.execute("DELETE FROM fingerprints WHERE id=?", (fp_id,))
    c.commit(); c.close()


def profile_breakdown(profile_id):
    c = _conn()
    rows = c.execute("""SELECT owasp,outcome,COUNT(*) as n FROM lessons
        WHERE profile_id=? GROUP BY owasp,outcome""", (profile_id,)).fetchall()
    c.close()
    breakdown = {}
    for r in rows:
        breakdown.setdefault(r["owasp"], {})[r["outcome"]] = r["n"]
    return breakdown


def export_profile(profile_id):
    c = _conn()
    profile = c.execute("SELECT * FROM profiles WHERE id=?",
                        (profile_id,)).fetchone()
    if not profile:
        c.close(); return {}
    lessons = c.execute("SELECT * FROM lessons WHERE profile_id=?",
                        (profile_id,)).fetchall()
    fps = c.execute("SELECT * FROM fingerprints WHERE profile_id=?",
                    (profile_id,)).fetchall()
    c.close()
    return {
        "version": 1,
        "exported_at": datetime.utcnow().isoformat(timespec="seconds"),
        "profile": dict(profile),
        "lessons": [dict(r) for r in lessons],
        "fingerprints": [dict(r) for r in fps],
    }


def import_profile(bundle, rename_to=None, merge_into_existing=False):
    if bundle.get("version") != 1 or "profile" not in bundle:
        raise ValueError("Invalid bundle format.")
    src = bundle["profile"]
    target_name = rename_to or src.get("name", "imported-profile")
    c = _conn()
    existing = c.execute("SELECT id FROM profiles WHERE name=?",
                         (target_name,)).fetchone()
    if existing and merge_into_existing:
        target_id = existing["id"]
    elif existing:
        base = target_name; i = 1
        while c.execute("SELECT id FROM profiles WHERE name=?",
                        (f"{base}-imported-{i}",)).fetchone():
            i += 1
        target_name = f"{base}-imported-{i}"
        cur = c.execute("INSERT INTO profiles(name,description,created,last_used) VALUES(?,?,?,?)",
            (target_name, src.get("description",""),
             datetime.utcnow().isoformat(timespec="seconds"),
             datetime.utcnow().isoformat(timespec="seconds")))
        target_id = cur.lastrowid
    else:
        cur = c.execute("INSERT INTO profiles(name,description,created,last_used) VALUES(?,?,?,?)",
            (target_name, src.get("description",""),
             datetime.utcnow().isoformat(timespec="seconds"),
             datetime.utcnow().isoformat(timespec="seconds")))
        target_id = cur.lastrowid

    count = 0
    for L in bundle.get("lessons", []):
        c.execute("""INSERT INTO lessons(profile_id,ts,owasp,technique,
            attack_name,prompt,outcome,severity,judge_rationale)
            VALUES(?,?,?,?,?,?,?,?,?)""",
            (target_id, L.get("ts"), L.get("owasp"), L.get("technique"),
             L.get("attack_name"), L.get("prompt"), L.get("outcome"),
             L.get("severity"), L.get("judge_rationale")))
        count += 1
    for F in bundle.get("fingerprints", []):
        c.execute("INSERT INTO fingerprints(profile_id,ts,recon_summary) VALUES(?,?,?)",
            (target_id, F.get("ts"), F.get("recon_summary")))
    c.commit(); c.close()
    return target_id, count


init_kb()