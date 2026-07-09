"""
COMPASS — Preuves vérifiables
Horodatage cryptographique des assessments NIS2.

Garanties apportées :
- Intégrité : le payload n'a pas été modifié depuis la génération
- Authenticité : le reçu est signé par le serveur COMPASS (HMAC-SHA256)
- Non-répudiation : l'empreinte est calculée au moment de la sauvegarde
  et stockée séparément du payload

Structure du reçu (Receipt) :
  {
    "assessment_id": 42,
    "org_name": "Acme SA",
    "assessed_at": "2026-07-09T12:00:00+00:00",
    "payload_hash": "sha256:<hex>",
    "receipt_id": "<uuid>",
    "issued_at": "2026-07-09T12:00:01+00:00",
    "algorithm": "HMAC-SHA256",
    "signature": "<hex>"   ← HMAC(secret, payload_hash|assessed_at|assessment_id)
  }

La clé HMAC est dérivée de COMPASS_SECRET_KEY (variable d'env).
En l'absence de variable d'env, une clé persistante est générée et
stockée dans ~/.nis2_analyzer/secret.key (jamais dans le code).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import uuid
from datetime import datetime, timezone
from pathlib import Path


# ── Clé secrète ──────────────────────────────────────────────────────────────

_KEY_FILE = Path(os.path.expanduser("~")) / ".nis2_analyzer" / "secret.key"


def _get_secret_key() -> bytes:
    """
    Retourne la clé HMAC.
    Ordre de priorité : variable d'env COMPASS_SECRET_KEY > fichier ~/.nis2_analyzer/secret.key.
    Si aucun des deux n'existe, génère et persiste une clé aléatoire 32 octets.
    """
    env_key = os.environ.get("COMPASS_SECRET_KEY", "")
    if env_key:
        return env_key.encode()

    if _KEY_FILE.exists():
        return _KEY_FILE.read_bytes()

    # Première exécution : génération
    _KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
    key = secrets.token_bytes(32)
    _KEY_FILE.write_bytes(key)
    _KEY_FILE.chmod(0o600)
    return key


# ── Calcul d'empreinte ────────────────────────────────────────────────────────

def compute_payload_hash(payload: dict) -> str:
    """
    Calcule le SHA-256 du payload JSON (trié, sans espaces).
    Retourne la chaîne "sha256:<hex>".
    """
    canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def _sign(payload_hash: str, assessed_at: str, assessment_id: int) -> str:
    """
    HMAC-SHA256 sur la concaténation des champs d'identité.
    Message signé : "<payload_hash>|<assessed_at>|<assessment_id>"
    """
    message = f"{payload_hash}|{assessed_at}|{assessment_id}".encode("utf-8")
    return hmac.new(_get_secret_key(), message, hashlib.sha256).hexdigest()


# ── Reçu de preuve ───────────────────────────────────────────────────────────

def build_receipt(
    assessment_id: int,
    org_name: str,
    assessed_at: str,
    payload_hash: str,
) -> dict:
    """
    Construit le reçu cryptographique pour un assessment.
    Le reçu peut être archivé par l'organisation comme preuve d'audit.
    """
    receipt_id = str(uuid.uuid4())
    issued_at = datetime.now(timezone.utc).isoformat()
    signature = _sign(payload_hash, assessed_at, assessment_id)

    return {
        "receipt_id": receipt_id,
        "assessment_id": assessment_id,
        "org_name": org_name,
        "assessed_at": assessed_at,
        "payload_hash": payload_hash,
        "issued_at": issued_at,
        "algorithm": "HMAC-SHA256",
        "signature": signature,
        "verification_instructions": (
            "Pour vérifier ce reçu, appelez GET /api/verify/{assessment_id} "
            "avec votre clé API et comparez le champ 'payload_hash' et 'signature' "
            "à ceux de ce document."
        ),
    }


def verify_receipt(
    assessment_id: int,
    org_name: str,
    assessed_at: str,
    stored_hash: str,
    current_payload: dict,
    stored_signature: str,
) -> dict:
    """
    Vérifie l'intégrité d'un assessment :
    1. Recalcule le hash du payload actuel
    2. Compare au hash stocké
    3. Vérifie la signature HMAC

    Retourne un rapport de vérification détaillé.
    """
    current_hash = compute_payload_hash(current_payload)
    hash_ok = hmac.compare_digest(current_hash, stored_hash)

    expected_sig = _sign(stored_hash, assessed_at, assessment_id)
    sig_ok = hmac.compare_digest(expected_sig, stored_signature)

    status = "VERIFIED" if (hash_ok and sig_ok) else "TAMPERED"
    issues = []
    if not hash_ok:
        issues.append("Le hash du payload ne correspond pas — le contenu a été modifié.")
    if not sig_ok:
        issues.append("La signature HMAC est invalide — le reçu ou la clé a changé.")

    return {
        "status": status,
        "assessment_id": assessment_id,
        "org_name": org_name,
        "assessed_at": assessed_at,
        "hash_check": "OK" if hash_ok else "FAIL",
        "signature_check": "OK" if sig_ok else "FAIL",
        "stored_hash": stored_hash,
        "computed_hash": current_hash,
        "issues": issues,
        "verified_at": datetime.now(timezone.utc).isoformat(),
    }
