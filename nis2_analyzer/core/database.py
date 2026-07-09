"""
COMPASS — Couche de persistance SQLite
Sauvegarde chaque assessment et permet le suivi de la progression dans le temps.

Schéma :
- tenants     : organisations (multi-tenant), authentification par clé API
- assessments : une ligne par évaluation, isolée par tenant_id
"""

import hashlib
import json
import os
import secrets
import sqlite3
from datetime import datetime, timezone


DEFAULT_DB_PATH = os.path.join(
    os.path.expanduser("~"), ".nis2_analyzer", "history.db"
)

# Tenant par défaut pour la compatibilité mono-tenant (sans clé API)
DEFAULT_TENANT_SLUG = "default"


def _get_connection(db_path: str = DEFAULT_DB_PATH) -> sqlite3.Connection:
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def _hash_key(api_key: str) -> str:
    return hashlib.sha256(api_key.encode()).hexdigest()


def init_db(db_path: str = DEFAULT_DB_PATH) -> None:
    """Crée la base et les tables si elles n'existent pas encore."""
    with _get_connection(db_path) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS tenants (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                slug        TEXT    NOT NULL UNIQUE,
                name        TEXT    NOT NULL,
                api_key_hash TEXT   NOT NULL UNIQUE,
                plan        TEXT    NOT NULL DEFAULT 'free',
                created_at  TEXT    NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS assessments (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id   INTEGER NOT NULL DEFAULT 1,
                org_name    TEXT    NOT NULL,
                assessed_at TEXT    NOT NULL,
                score       REAL    NOT NULL,
                grade       TEXT    NOT NULL,
                total_gaps  INTEGER NOT NULL,
                payload     TEXT    NOT NULL,
                FOREIGN KEY (tenant_id) REFERENCES tenants(id)
            )
        """)
        # Migration : ajouter tenant_id si la table existait sans cette colonne
        cols = {r[1] for r in conn.execute("PRAGMA table_info(assessments)")}
        if "tenant_id" not in cols:
            conn.execute("ALTER TABLE assessments ADD COLUMN tenant_id INTEGER NOT NULL DEFAULT 1")
        # Créer le tenant "default" s'il n'existe pas
        existing = conn.execute(
            "SELECT id FROM tenants WHERE slug = ?", (DEFAULT_TENANT_SLUG,)
        ).fetchone()
        if not existing:
            default_key = secrets.token_urlsafe(32)
            conn.execute(
                """INSERT INTO tenants (slug, name, api_key_hash, plan, created_at)
                   VALUES (?, ?, ?, 'free', ?)""",
                (DEFAULT_TENANT_SLUG, "Default", _hash_key(default_key),
                 datetime.now(timezone.utc).isoformat()),
            )


# ── Gestion des tenants ───────────────────────────────────────────────────────

def create_tenant(name: str, slug: str, plan: str = "free",
                  db_path: str = DEFAULT_DB_PATH) -> dict:
    """
    Crée un nouveau tenant et retourne sa clé API en clair (une seule fois).
    La clé n'est JAMAIS stockée en clair — seulement son hash SHA-256.
    """
    init_db(db_path)
    api_key = secrets.token_urlsafe(32)
    key_hash = _hash_key(api_key)
    created_at = datetime.now(timezone.utc).isoformat()
    with _get_connection(db_path) as conn:
        try:
            cursor = conn.execute(
                """INSERT INTO tenants (slug, name, api_key_hash, plan, created_at)
                   VALUES (?, ?, ?, ?, ?)""",
                (slug, name, key_hash, plan, created_at),
            )
            tenant_id = cursor.lastrowid
        except sqlite3.IntegrityError as e:
            raise ValueError(f"Slug '{slug}' déjà utilisé.") from e
    return {
        "id": tenant_id,
        "slug": slug,
        "name": name,
        "plan": plan,
        "created_at": created_at,
        "api_key": api_key,  # retourné une seule fois, non stocké en clair
    }


def get_tenant_by_key(api_key: str, db_path: str = DEFAULT_DB_PATH) -> dict | None:
    """Résout une clé API → tenant. Retourne None si invalide."""
    init_db(db_path)
    key_hash = _hash_key(api_key)
    with _get_connection(db_path) as conn:
        row = conn.execute(
            "SELECT id, slug, name, plan, created_at FROM tenants WHERE api_key_hash = ?",
            (key_hash,),
        ).fetchone()
    return dict(row) if row else None


def get_default_tenant_id(db_path: str = DEFAULT_DB_PATH) -> int:
    """Retourne l'id du tenant 'default' (compatibilité mono-tenant)."""
    init_db(db_path)
    with _get_connection(db_path) as conn:
        row = conn.execute(
            "SELECT id FROM tenants WHERE slug = ?", (DEFAULT_TENANT_SLUG,)
        ).fetchone()
    return row["id"] if row else 1


def list_tenants(db_path: str = DEFAULT_DB_PATH) -> list[dict]:
    """Liste tous les tenants (sans les clés API)."""
    init_db(db_path)
    with _get_connection(db_path) as conn:
        rows = conn.execute(
            "SELECT id, slug, name, plan, created_at FROM tenants ORDER BY created_at"
        ).fetchall()
    return [dict(r) for r in rows]


# ── Assessments (tenant-scoped) ───────────────────────────────────────────────

def save_assessment(analysis: dict, db_path: str = DEFAULT_DB_PATH,
                    tenant_id: int | None = None) -> int:
    """
    Persiste un assessment complet et retourne son id.
    Si tenant_id est None, utilise le tenant 'default'.
    """
    init_db(db_path)
    if tenant_id is None:
        tenant_id = get_default_tenant_id(db_path)

    scores = analysis.get("scores", {})
    org_name = analysis.get("metadata", {}).get("organization", "Inconnue")
    assessed_at = datetime.now(timezone.utc).isoformat()
    score = scores.get("overall_score", 0.0)
    grade = scores.get("grade", "?")
    total_gaps = scores.get("total_gaps", 0)
    payload = json.dumps(analysis, ensure_ascii=False)

    with _get_connection(db_path) as conn:
        cursor = conn.execute(
            """INSERT INTO assessments
               (tenant_id, org_name, assessed_at, score, grade, total_gaps, payload)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (tenant_id, org_name, assessed_at, score, grade, total_gaps, payload),
        )
        return cursor.lastrowid


def list_assessments(org_name: str = None, limit: int = 20,
                     db_path: str = DEFAULT_DB_PATH,
                     tenant_id: int | None = None) -> list[dict]:
    """Retourne les assessments du tenant, filtrés optionnellement par org."""
    init_db(db_path)
    if tenant_id is None:
        tenant_id = get_default_tenant_id(db_path)
    with _get_connection(db_path) as conn:
        if org_name:
            rows = conn.execute(
                """SELECT id, org_name, assessed_at, score, grade, total_gaps
                   FROM assessments
                   WHERE tenant_id = ? AND org_name LIKE ?
                   ORDER BY assessed_at DESC LIMIT ?""",
                (tenant_id, f"%{org_name}%", limit),
            ).fetchall()
        else:
            rows = conn.execute(
                """SELECT id, org_name, assessed_at, score, grade, total_gaps
                   FROM assessments
                   WHERE tenant_id = ?
                   ORDER BY assessed_at DESC LIMIT ?""",
                (tenant_id, limit),
            ).fetchall()
    return [dict(r) for r in rows]


def get_assessment(assessment_id: int, db_path: str = DEFAULT_DB_PATH,
                   tenant_id: int | None = None) -> dict | None:
    """Charge un assessment par id, vérifie l'appartenance au tenant."""
    init_db(db_path)
    if tenant_id is None:
        tenant_id = get_default_tenant_id(db_path)
    with _get_connection(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM assessments WHERE id = ? AND tenant_id = ?",
            (assessment_id, tenant_id),
        ).fetchone()
    if row is None:
        return None
    result = dict(row)
    result["payload"] = json.loads(result["payload"])
    return result


def compare_assessments(id_a: int, id_b: int,
                        db_path: str = DEFAULT_DB_PATH,
                        tenant_id: int | None = None) -> dict:
    """
    Compare deux assessments et retourne le delta score + gaps par domaine.
    id_a = le plus ancien, id_b = le plus récent.
    """
    a = get_assessment(id_a, db_path, tenant_id)
    b = get_assessment(id_b, db_path, tenant_id)

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
