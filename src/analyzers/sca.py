"""sca.py — Software Composition Analysis: detecta dependencias vulnerables.

A diferencia de SAST y Secrets que buscan patrones regex línea por línea,
SCA analiza archivos de manifiesto de dependencias (requirements.txt,
pyproject.toml, etc.) y compara las versiones de cada paquete contra
una base de vulnerabilidades conocidas (reglas JSON).
"""

from __future__ import annotations
import json
import re
from dataclasses import dataclass
from pathlib import Path
from ..domain import Category, FileInfo, Finding, Severity
from ..ports import IAnalyzer
from . import osv as osv_client

# Nombres de archivos manifest que el analyzer sabe parsear.
# Si un archivo no está en esta lista, se ignora inmediatamente
# sin intentar parsearlo (ahorra lecturas innecesarias).
_MANIFEST_NAMES: frozenset[str] = frozenset({
    "requirements.txt",
    "pyproject.toml",
    "Pipfile",
    "Pipfile.lock",
    "setup.py",
    "setup.cfg",
})

# Regex para línea tipo: "django==4.2.1" o "requests>=2.31.0"
#   grupo 1: nombre del paquete (letras, números, _, -, .)
#   grupo 2: operador de versión (==, >=, <=, !=, ~=, >, <)
#   grupo 3: número de versión (ej: 4.2.1, 2.31.0, 3.2.*)
# Nota: no captura líneas sin operador como "django" (sin versión pinneada
# no podemos evaluar vulnerabilidad).
_REQ_LINE = re.compile(r"^([a-zA-Z0-9_.-]+)\s*([><=!~]+)\s*([a-zA-Z0-9_.*]+)")

# Regex para línea tipo: django = ">=4.2.0" dentro de pyproject.toml
#   grupo 1: nombre del paquete
#   grupo 2: versión dentro de las comillas (incluye operador)
# No maneja: extras (django[bcrypt]), URLs, ni rangos fuera de comillas.
_TOML_DEP = re.compile(r'^([a-zA-Z0-9_.-]+)\s*=\s*"[><=!~]+\s*([a-zA-Z0-9_.*]+)"')


@dataclass(frozen=True, slots=True)
class ScaRule:
    """Regla SCA: asocia un paquete y restricción de versión vulnerable.

    A diferencia de las reglas SAST (que tienen un pattern regex),
    una regla SCA tiene:
      - package: nombre del paquete (ej: "django")
      - version_constraint: restricción semántica (ej: "<3.2.25")
    """
    id: str
    title: str
    severity: Severity
    package: str
    version_constraint: str


def _parse_version(v: str) -> tuple[int, ...]:
    """Convierte '3.2.25' → (3, 2, 25) para comparación numérica.

    ¿Por qué tuplas y no strings?
      - Comparar versiones como strings falla: "10.0" < "9.0" es True
        porque '1' < '9' lexicográficamente.
      - En cambio (10, 0) > (9, 0) porque Python compara tupla elemento
        a elemento numéricamente: primero el major, si empatan sigue
        el minor, luego el patch.

    Maneja separadores mixtos: "3.2.25", "3.2_25", "3.2-25" todos
    producen (3, 2, 25). Si un segmento no es numérico (ej: "rc1"),
    se asigna 0 — no es perfecto pero evita crasheos.
    """
    parts = v.replace("-", ".").replace("_", ".").split(".")
    result: list[int] = []
    for p in parts:
        try:
            result.append(int(p))
        except ValueError:
            result.append(0)
    return tuple(result)


def _matches_constraint(version: str, constraint: str) -> bool:
    """Evalúa si una versión cumple una restricción tipo '>=1.0,<2.0'.

    El formato sigue el estándar de pip: el constraint es una o más
    condiciones separadas por coma que se evalúan como AND lógico
    (TODAS deben cumplirse).

    Cómo funciona internamente:
      1. Divide el constraint por coma → partes individuales
         Ej: ">=4.0,<4.10" → [">=4.0", "<4.10"]
      2. Cada parte se descompone en (operador, version_target):
         - Operador: uno de ==, !=, >, >=, <, <=
         - Version target: se parsea a tupla con _parse_version
      3. Compara la versión actual contra el target usando el operador:
         - (4, 0, 0) >= (4, 0, 0) → True
         - (4, 0, 0) < (4, 10, 0) → True
         - Ambas True → la versión cumple el rango
      4. Si alguna parte NO se cumple, retorna False inmediatamente.
         Si todas se cumplen, retorna True.

    Ejemplos concretos:
      version="3.2.20", constraint="<3.2.25"
        → (3,2,20) < (3,2,25) → True  (vulnerable)

      version="4.2.0", constraint=">=4.0.0,<4.2.16"
        → (4,2,0) >= (4,0,0) → True
        → (4,2,0) < (4,2,16) → True
        → ambas True → True (vulnerable)

      version="4.2.20", constraint=">=4.0.0,<4.2.16"
        → (4,2,20) >= (4,0,0) → True
        → (4,2,20) < (4,2,16) → False
        → una False → False (seguro, versión parcheada)
    """
    v = _parse_version(version)
    parts = [c.strip() for c in constraint.split(",")]
    for part in parts:
        m = re.match(r"^(>=|<=|!=|==|>|<)\s*([\w.*-]+)$", part)
        if not m:
            continue
        op, target_str = m.group(1), m.group(2)
        t = _parse_version(target_str)
        if op == "==" and v != t:
            return False
        if op == "!=" and v == t:
            return False
        if op == ">" and not (v > t):
            return False
        if op == ">=" and not (v >= t):
            return False
        if op == "<" and not (v < t):
            return False
        if op == "<=" and not (v <= t):
            return False
    return True


def _parse_requirements(text: str) -> list[tuple[str, str]]:
    """Extrae (nombre_paquete, version) de un requirements.txt.

    Solo reconoce líneas con operador de versión explícito.
    Una línea como "django==4.2.1" produce ("django", "4.2.1").
    Una línea como "django" (sin operador) se ignora porque
    sin versión concreta no podemos evaluar vulnerabilidad.

    Líneas ignoradas intencionalmente:
      - Comentarios (#) → no son dependencias
      - Opciones pip (-r, --index-url, etc.) → no son paquetes
      - Paquetes sin versión (solo "django") → no tenemos qué comparar
    """
    pkgs: list[tuple[str, str]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        m = _REQ_LINE.match(line)
        if m:
            pkgs.append((m.group(1).lower(), m.group(3)))
    return pkgs


def _parse_pyproject_toml(text: str) -> list[tuple[str, str]]:
    """Extrae (nombre_paquete, version) de [project] dependencies.

    Busca líneas como:
      django = ">=4.2.0"

    Cómo funciona el parsing:
      1. Busca una línea que contenga "[project" y "dependencies"
         (ej: [project.dependencies]) y activa modo parsing.
      2. Al encontrar cualquier otra sección "[...]", desactiva
         el modo — las dependencias ya terminaron.
      3. Dentro de la sección activa, cada línea se evalúa contra
         _TOML_DEP: captura nombre y versión entre comillas.

    Limitaciones conocidas:
      - No maneja dependencias opcionales ([project.optional-dependencies])
      - No maneja extras: django[bcrypt]>=4.2.0
      - No maneja dependencias por URL: django @ https://...
      - No maneja versiones con comillas escapadas
      - pyproject.toml es técnicamente TOML, pero este parser es
        textual (línea por línea) para evitar importar tomllib.
        Esto es frágil si el formato se desvía del estándar de pip.
    """
    pkgs: list[tuple[str, str]] = []
    in_deps = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("[") and "dependencies" in stripped:
            in_deps = "project" in stripped and "dependencies" in stripped
            continue
        if stripped.startswith("["):
            in_deps = False
        if not in_deps:
            continue
        m = _TOML_DEP.match(stripped)
        if m:
            pkgs.append((m.group(1).lower(), m.group(2)))
    return pkgs


def _parse_manifest(file: FileInfo) -> list[tuple[str, str]]:
    """Selecciona el parser adecuado según el nombre del archivo.

    Cada formato de manifest tiene estructura radicalmente distinta:
      - requirements.txt: una dependencia por línea, formato plano
      - pyproject.toml:   TOML con secciones anidadas

    Si el archivo no está en _MANIFEST_NAMES, retorna [] sin intentar
    parsear. Esto evita errores tontos como tratar de parsear cualquier
    .txt como si fuera requirements.txt.
    """
    try:
        text = file.absolute.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    name = file.absolute.name
    if name == "requirements.txt":
        return _parse_requirements(text)
    if name == "pyproject.toml":
        return _parse_pyproject_toml(text)
    return []


def _load_sca_rules(rules_dir: Path) -> list[ScaRule]:
    """Carga reglas SCA desde archivos JSON en rules_dir.

    Diferencia crucial con load_rules de _base.py (SAST/Secrets):
      - SAST usa reglas con 'pattern' (regex) para buscar en cada línea
      - SCA usa reglas con 'package' + 'version_constraint' para
        comparar contra pares (nombre, versión) extraídos del manifest

    Formato de cada regla en el JSON:
      {
        "id": "PYA001",
        "package": "django",
        "version_constraint": "<3.2.25",
        "severity": "high",
        "title": "Django < 3.2.25 — SQL injection"
      }

    Reglas inválidas (campo faltante, severidad incorrecta, JSON malformado)
    se saltan en silencio, misma política que SAST/Secrets. Esto permite
    tener archivos JSON vacíos o incompletos sin romper el escaneo.
    """
    rules: list[ScaRule] = []
    for json_file in sorted(rules_dir.glob("*.json")):
        try:
            raw = json.loads(json_file.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        for r in raw:
            try:
                rules.append(
                    ScaRule(
                        id=r["id"],
                        title=r["title"],
                        severity=Severity(r["severity"]),
                        package=r["package"].lower(),
                        version_constraint=r["version_constraint"],
                    )
                )
            except (KeyError, ValueError):
                continue
    return rules


class ScaAnalyzer(IAnalyzer):
    """Adaptador SCA: chequea manifests contra vulnerabilidades conocidas.

    Soporta dos fuentes de datos:
      - OSV.dev: base de datos en tiempo real con millones de CVEs
      - Reglas locales: JSON manual (rules/sca/pypi.json)

    La fuente se configura con el parámetro `source`:
      - "both" (default): OSV primero, si falla o no encuentra, usa local
      - "osv": solo OSV, ignora reglas locales
      - "local": solo reglas locales (comportamiento original)

    Flujo de analyze(file):
      1. Filtro rápido: si el nombre del archivo no está en
         _MANIFEST_NAMES, retorna [] — no es un manifest.
      2. Parsing: según el nombre, elige el parser adecuado y extrae
         pares (nombre_paquete, version).
      3. Para cada par, según la fuente configurada:
         - OSV: consulta api.osv.dev (con caché local de 24h)
         - Local: recorre _rules y compara con _matches_constraint
      4. Retorna la lista de findings.

    Diferencia fundamental con SAST/Secrets:
      - SAST busca PATRONES REGEX en cada línea → detecta malas prácticas
      - SCA busca ESTRUCTURAS (nombre + versión) en manifests y las
        compara contra una base de vulnerabilidades conocidas
    """

    def __init__(self, rules_dir: str | Path, source: str = "both") -> None:
        self._rules = _load_sca_rules(Path(rules_dir))
        self._source = source

    def analyze(self, file: FileInfo) -> list[Finding]:
        if file.absolute.name not in _MANIFEST_NAMES:
            return []
        pkgs = _parse_manifest(file)
        if not pkgs:
            return []
        findings: list[Finding] = []
        for pkg_name, pkg_version in pkgs:
            osv_findings: list[Finding] = []
            local_findings: list[Finding] = []

            if self._source in ("osv", "both"):
                try:
                    vulns = osv_client.query("PyPI", pkg_name, pkg_version)
                except Exception:
                    vulns = []
                for ov in vulns:
                    snippet = f"{pkg_name}=={pkg_version}"
                    if ov.fixed:
                        snippet += f" (fix: {ov.fixed})"
                    osv_findings.append(Finding(
                        rule_id=ov.id,
                        title=ov.summary,
                        severity=ov.severity,
                        category=Category.SCA,
                        file=file,
                        line=1,
                        snippet=snippet,
                    ))

            if self._source in ("local",) or (self._source == "both" and not osv_findings):
                for rule in self._rules:
                    if pkg_name != rule.package:
                        continue
                    if _matches_constraint(pkg_version, rule.version_constraint):
                        local_findings.append(Finding(
                            rule_id=rule.id,
                            title=rule.title,
                            severity=rule.severity,
                            category=Category.SCA,
                            file=file,
                            line=1,
                            snippet=f"{pkg_name}=={pkg_version}",
                        ))

            findings.extend(osv_findings if osv_findings else local_findings)

        return findings
