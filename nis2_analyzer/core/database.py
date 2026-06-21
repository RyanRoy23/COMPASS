"""
COMPASS — Couche de persistance SQLite
Sauvegarde chaque assessment et permet le suivi de la progression dans le temps.

Pourquoi SQLite et pas un fichier JSON par assessment ?
- Un fichier par assessment devient vite ingérable (nommage, recherche, tri)
- SQLite est intégré à Python (stdlib), zéro dépendance supplémentaire
- Requêtes simples pour comparer deux assessments ou lister l'historique
- Le fichier .db est portable : un seul fichier à sauvegarder/transférer

Schéma :
- assessments : une ligne par évaluation (métadonnées + score + JSON complet)
"""

import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path


DEFAULT_DB_PATH = os.path.join(
    os.path.expanduser("~"), ".nis2_analyzer", "history.db"
)


def _get_connection(db_path: str = DEFAULT_DB_PATH) -> sqlite3.Connection:
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: str = DEFAULT_DB_PATH) -> None:
    """Crée la base et les tables si elles n'existent pas encore."""
    with _get_connection(db_path) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS assessments (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                org_name    TEXT    NOT NULL,
                assessed_at TEXT    NOT NULL,
                score       REAL    NOT NULL,
                grade       TEXT    NOT NULL,
                total_gaps  INTEGER NOT NULL,
                payload     TEXT    NOT NULL
            )
        """)


def save_assessment(analysis: dict, db_path: str = DEFAULT_DB_PATH) -> int:
    """
    Persiste un assessment complet et retourne son id.

    `analysis` est le dict produit par ScoringEngine.full_analysis().
    On stocke les méta-données en colonnes pour des requêtes rapides,
    et le dict complet en JSON dans payload pour ne rien perdre.
    """
    init_db(db_path)

    scores = analysis.get("scores", {})
    org_name = analysis.get("metadata", {}).get("organization", "Inconnue")
    assessed_at = datetime.now(timezone.utc).isoformat()
    score = scores.get("overall_score", 0.0)
    grade = scores.get("grade", "?")
    total_gaps = scores.get("total_gaps", 0)
    payload = json.dumps(analysis, ensure_ascii=False)

    with _get_connection(db_path) as conn:
        cursor = conn.execute(
            """
            INSERT INTO assessments (org_name, assessed_at, score, grade, total_gaps, payload)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (org_name, assessed_at, score, grade, total_gaps, payload),
        )
        return cursor.lastrowid


def list_assessments(org_name: str = None, limit: int = 20,
                     db_path: str = DEFAULT_DB_PATH) -> list[dict]:
    """
    Retourne les derniers assessments, optionnellement filtrés par organisation.
    """
    init_db(db_path)
    with _get_connection(db_path) as conn:
        if org_name:
            rows = conn.execute(
                """
                SELECT id, org_name, assessed_at, score, grade, total_gaps
                FROM assessments
                WHERE org_name LIKE ?
                ORDER BY assessed_at DESC
                LIMIT ?
                """,
                (f"%{org_name}%", limit),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT id, org_name, assessed_at, score, grade, total_gaps
                FROM assessments
                ORDER BY assessed_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
    return [dict(r) for r in rows]


def get_assessment(assessment_id: int, db_path: str = DEFAULT_DB_PATH) -> dict | None:
    """Charge un assessment complet par son id."""
    init_db(db_path)
    with _get_connection(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM assessments WHERE id = ?", (assessment_id,)
        ).fetchone()
    if row is None:
        return None
    result = dict(row)
    result["payload"] = json.loads(result["payload"])
    return result


def compare_assessments(id_a: int, id_b: int,
                        db_path: str = DEFAULT_DB_PATH) -> dict:
    """
    Compare deux assessments et retourne le delta score + gaps par domaine.
    id_a = le plus ancien, id_b = le plus récent.
    """
    a = get_assessment(id_a, db_path)
    b = get_assessment(id_b, db_path)

    if a is None or b is None:
        missing = id_a if a is None else id_b
        raise ValueError(f"Assessment #{missing} introuvable.")

    score_a = a["score"]
    score_b = b["score"]

    domain_deltas = []
    domains_a = {d["title"]: d for d in a["payload"].get("domains", [])}
    domains_b = {d["title"]: d for d in b["payload"].get("domains", [])}

    for title, d_b in domains_b.items():
        d_a = domains_a.get(title)
        score_before = d_a["score"] if d_a else None
        score_after = d_b["score"]
        delta = round(score_after - score_before, 1) if score_before is not None else None
        domain_deltas.append({
            "domain": title,
            "score_before": score_before,
            "score_after": score_after,
            "delta": delta,
        })

    return {
        "org_name": b["org_name"],
        "date_before": a["assessed_at"],
        "date_after": b["assessed_at"],
        "score_before": score_a,
        "score_after": score_b,
        "score_delta": round(score_b - score_a, 1),
        "gaps_before": a["total_gaps"],
        "gaps_after": b["total_gaps"],
        "gaps_delta": b["total_gaps"] - a["total_gaps"],
        "grade_before": a["grade"],
        "grade_after": b["grade"],
        "domains": domain_deltas,
    }
