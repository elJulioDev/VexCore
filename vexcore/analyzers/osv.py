"""osv.py — Cliente para OSV.dev (Open Source Vulnerabilities).

Conecta con https://api.osv.dev/v1/query para obtener vulnerabilidades
reales de cualquier ecosistema (PyPI, npm, Go, etc.).

Cachea respuestas en ~/.cache/vexcore/osv/ con TTL de 24 horas para
evitar repetir queries por el mismo (paquete, version) en escaneos
consecutivos.

Sin dependencias externas — usa urllib.request de la stdlib.
"""

from __future__ import annotations
import hashlib
import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from ..domain import Severity

CACHE_DIR = Path.home() / ".cache" / "vexcore" / "osv"
CACHE_TTL = 86400  # 24 horas en segundos

OSV_URL = "https://api.osv.dev/v1/query"


@dataclass(frozen=True, slots=True)
class OsvVuln:
    """Vulnerabilidad reportada por OSV.dev.

    Atributos:
        id: Identificador (GHSA-xxxx, CVE-xxxx)
        summary: Descripción corta de la vulnerabilidad
        severity: Severidad traducida de CVSS/GHSA
        fixed: Versión que corrige la vulnerabilidad (None si no se
               encontró, ej: "3.2.25")
    """
    id: str
    summary: str
    severity: Severity
    fixed: str | None


def _cache_key(package: str, ecosystem: str, version: str) -> str:
    """Genera nombre de archivo hash para evitar problemas con
    caracteres especiales en nombres de paquete o versión."""
    raw = f"{ecosystem}|{package}|{version}"
    return hashlib.sha256(raw.encode()).hexdigest() + ".json"


def _cache_path(package: str, ecosystem: str, version: str) -> Path:
    return CACHE_DIR / _cache_key(package, ecosystem, version)


def _load_cache(package: str, ecosystem: str, version: str) -> list[OsvVuln] | None:
    """Lee respuesta cacheada del disco.

    Retorna None si:
      - El archivo no existe (nunca se consultó antes)
      - El archivo expiró (> CACHE_TTL desde última modificación)
      - El archivo está corrupto (JSON inválido)
    """
    path = _cache_path(package, ecosystem, version)
    if not path.exists():
        return None
    edad = time.time() - path.stat().st_mtime
    if edad > CACHE_TTL:
        return None
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        return _parse_response(raw)
    except (json.JSONDecodeError, OSError):
        return None


def _save_cache(package: str, ecosystem: str, version: str, data: dict) -> None:
    """Guarda respuesta de OSV en ~/.cache/vexcore/osv/<hash>.json.

    Crea directorios si no existen. El TTL se controla por fecha
    de modificación del archivo, no por contenido.
    """
    path = _cache_path(package, ecosystem, version)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def _extract_severity(vuln: dict) -> Severity:
    """Extrae severity de una vulnerabilidad OSV.

    OSV no tiene un campo severity único y consistente porque los datos
    provienen de distintas fuentes (GitHub Security Advisories, CVEs
    de NVD, etc.). Cada fuente usa su propio formato.

    Estrategia probando varias fuentes (por orden de prioridad):

    1. database_specific.severity → string como "CRITICAL" o "HIGH"
       Es el campo más común en GHSA (GitHub Security Advisories).
       Ejemplo: {"database_specific": {"severity": "HIGH"}}

    2. severity[].score → número float (CVSS v3 score)
       Score numérico normalizado de Common Vulnerability Scoring System.
       Rangos estándar:
         - >= 9.0 → CRITICAL
         - >= 7.0 → HIGH
         - >= 4.0 → MEDIUM
         - >= 1.0 → LOW

    3. Si ninguna funciona → Severity.MEDIUM como default conservador.
       Es preferible reportar de más (falso positivo) que dejar pasar
       una vulnerabilidad por no tener severity.
    """
    db_spec = vuln.get("database_specific", {})
    if isinstance(db_spec, dict):
        sev_str = db_spec.get("severity")
        if isinstance(sev_str, str):
            ups = sev_str.upper()
            if ups in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
                return Severity(ups.lower())

    for s in vuln.get("severity", []):
        score_str = s.get("score", "")
        try:
            score = float(score_str)
            if score >= 9.0:
                return Severity.CRITICAL
            if score >= 7.0:
                return Severity.HIGH
            if score >= 4.0:
                return Severity.MEDIUM
            if score >= 1.0:
                return Severity.LOW
        except ValueError:
            continue

    return Severity.MEDIUM


def _extract_fixed(vuln: dict) -> str | None:
    """Busca la versión que corrige la vulnerabilidad en la respuesta OSV.

    OSV estructura las versiones como rangos dentro de affected[].
    Cada rango tiene eventos que marcan introduced (desde dónde es
    vulnerable) y fixed (versión que lo corrige).

    Ejemplo de estructura:
      {
        "affected": [{
          "ranges": [{
            "type": "ECOSYSTEM",
            "events": [
              {"introduced": "0"},
              {"fixed": "3.2.25"}
            ]
          }]
        }]
      }

    Retorna la primera versión "fixed" que encuentre, o None si no hay.
    """
    for aff in vuln.get("affected", []):
        for rng in aff.get("ranges", []):
            for evt in rng.get("events", []):
                if "fixed" in evt:
                    return str(evt["fixed"])
    return None


def _parse_response(data: dict) -> list[OsvVuln]:
    """Convierte respuesta JSON de OSV.dev a lista de OsvVuln.

    La respuesta tiene la estructura:
      {
        "vulns": [
          {
            "id": "GHSA-xxxx",
            "summary": "SQL injection in Django",
            "severity": [{"type": "CVSS_V3", "score": "7.5"}],
            "database_specific": {"severity": "HIGH"},
            "affected": [...]
          }
        ]
      }

    Cada ítem en "vulns" se parsea a OsvVuln con:
      - id: string identificador
      - summary: descripción corta (fallback a details si summary falta)
      - severity: traducido con _extract_severity
      - fixed: primera versión que corrige (None si no hay)
    """
    result: list[OsvVuln] = []
    for v in data.get("vulns", []):
        result.append(OsvVuln(
            id=v.get("id", "unknown"),
            summary=v.get("summary", v.get("details", "")),
            severity=_extract_severity(v),
            fixed=_extract_fixed(v),
        ))
    return result


def query(ecosystem: str, package: str, version: str) -> list[OsvVuln]:
    """Consulta vulnerabilidades de un (paquete, version) en OSV.dev.

    Flujo completo:
      1. Revisa caché local (~/.cache/vexcore/osv/<hash>.json)
         - Si existe y tiene menos de 24h → usa caché (rápido, 0ms)
         - Si no existe o expiró → continúa al paso 2
      2. Hace POST a https://api.osv.dev/v1/query con los datos del
         paquete. La API es gratuita y no requiere autenticación.
      3. Guarda la respuesta en caché para futuras consultas.
      4. Parsea y retorna lista de OsvVuln.

    Args:
        ecosystem: Ecosistema (ej: "PyPI", "npm", "Go")
        package: Nombre del paquete (ej: "django")
        version: Versión específica (ej: "3.2.20")

    Returns:
        Lista de OsvVuln. Vacía si no hay vulnerabilidades conocidas
        o si la API no está disponible.

    Notas:
        - No requiere internet: si la API falla, retorna [] vacío
          y el llamador decide si usar fallback local.
        - Sin API key, sin límite de rate documentado para uso normal.
    """
    cached = _load_cache(package, ecosystem, version)
    if cached is not None:
        return cached

    payload = json.dumps({
        "package": {"name": package, "ecosystem": ecosystem},
        "version": version,
    }).encode("utf-8")

    req = urllib.request.Request(
        OSV_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            raw = json.loads(resp.read())
    except (urllib.error.URLError, urllib.error.HTTPError, OSError, json.JSONDecodeError):
        return []

    _save_cache(package, ecosystem, version, raw)
    return _parse_response(raw)
