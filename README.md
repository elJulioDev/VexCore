# VexCore

Escáner estático de seguridad: **SAST**, **detección de secretos**, **configuración insegura** y **análisis de dependencias (SCA)**, diseñado con **Arquitectura Hexagonal** (Puertos y Adaptadores).

Las reglas son archivos JSON incluidos en el paquete, el motor es extensible con plugins y la salida se integra en CI (JSON, SARIF y códigos de salida).

## Características

- **SAST por regex** para Python/Django, JavaScript/TypeScript, PHP, Go, Java y Ruby.
- **SAST por AST para Python**: detecta `eval()`, `exec()`, `os.system()`, `subprocess.*` y `pickle.load(s)` analizando el árbol sintáctico, así que no reacciona a menciones en comentarios o strings.
- **Secretos**: AWS keys, tokens de GitHub, webhooks de Slack, claves de Stripe, JWT secrets, contraseñas hardcodeadas, etc.
- **Configuración insegura**: `.env`, `docker-compose` y `settings.py` de Django (desactivado por defecto).
- **SCA**: dependencias Python con versiones vulnerables, consultando [OSV.dev](https://osv.dev) con caché local de 24 h y reglas locales de respaldo (desactivado por defecto).
- **Salidas**: consola con colores, JSON y SARIF (GitHub Code Scanning).
- **CI-friendly**: código de salida `1` según severidad (`--fail-on`).
- **Rendimiento**: análisis en paralelo, recorrido lazy del sistema de archivos y modo incremental.
- **Supresiones** con `.vexcoreignore`, **plugins** propios y uso como **librería Python**.
- **TUI** interactiva con [Textual](https://textual.textualize.io/).

## Requisitos

- Python >= 3.11
- [`uv`](https://docs.astral.sh/uv/) (recomendado) o `pip`

## Instalación

```bash
git clone https://github.com/elJulioDev/VexCore.git
cd VexCore
uv sync
```

## Uso

```bash
# Escaneo básico (desde el repo: uv run vexcore ...)
vexcore ./mi_proyecto

# Severidad mínima a reportar: critical, high, medium, low, info
vexcore ./mi_proyecto --severity high

# Salida JSON o SARIF
vexcore ./mi_proyecto --output json
vexcore ./mi_proyecto --output sarif > vexcore.sarif

# En CI: falla (exit 1) solo si hay hallazgos high o critical
vexcore ./mi_proyecto --fail-on high

# Solo re-escanear archivos modificados desde la última ejecución
vexcore ./mi_proyecto --incremental

# Interfaz interactiva
vexcore --tui ./mi_proyecto
```

| Opción | Descripción |
|--------|-------------|
| `target` | Directorio a escanear. |
| `-c`, `--config` | Ruta a un `config.yaml` (ver [Configuración](#configuración)). |
| `--severity` | Severidad mínima a reportar. Sobrescribe `output.severity_threshold`. |
| `--output` | `console` (por defecto), `json` o `sarif`. |
| `--fail-on` | Devuelve exit `1` si hay hallazgos de esta severidad o superior. Por defecto, igual a `--severity`. |
| `--no-color` | Desactiva los colores. También se desactivan si la salida no es una terminal o si `NO_COLOR` está definido. |
| `--incremental` | Usa una caché de hashes en `~/.vexcore/cache/` para analizar solo los archivos que cambiaron. |
| `--tui` | Abre la interfaz interactiva. |

**Códigos de salida:** `0` sin hallazgos por encima de `--fail-on`; `1` si los hay o si hay un error (directorio o config inválidos, reglas no encontradas).

## Configuración

VexCore busca la configuración en este orden y usa la primera que encuentra:

1. La ruta indicada con `-c/--config`
2. `config.yaml` en el directorio actual
3. `~/.vexcore/config.yaml` (configuración global)
4. Valores por defecto

```yaml
crawler:
  # Si se omiten, se usan las listas por defecto de vexcore/crawler.py,
  # que cubren todos los lenguajes con reglas. Si se definen, las REEMPLAZAN.
  # ignore_dirs: [.git, node_modules, venv]
  # scan_extensions: [.py, .js, .php]
  max_file_size_mb: 5
  follow_symlinks: false

analyzers:
  sast:
    enabled: true
  secrets:
    enabled: true
  sca:
    enabled: false
    source: both      # both (OSV + local), osv (solo API), local (sin red)
  config:
    enabled: false

plugins_dir: plugins
incremental: false

output:
  severity_threshold: low
```

### Reglas propias

Las reglas vienen dentro del paquete (`vexcore/rules/`), así que VexCore funciona desde cualquier directorio. Para usar las tuyas, añade `rules_path` al analizador. Las rutas relativas (también `plugins_dir`) se resuelven **desde el directorio del `config.yaml`**, no desde el directorio actual:

```yaml
analyzers:
  sast:
    rules_path: mis-reglas/sast
```

Si un analizador activado no encuentra su directorio de reglas, VexCore termina con un error en lugar de escanear sin reglas.

### SCA

Con `sca.enabled: true` se analizan `requirements.txt`, `pyproject.toml`, `Pipfile`, `Pipfile.lock`, `setup.py` y `setup.cfg`. Las versiones se comparan semánticamente (no con regex) contra:

- **both** (por defecto): [OSV.dev](https://osv.dev) y, si falla la conexión, las reglas locales (`vexcore/rules/sca/`).
- **osv**: solo OSV.dev.
- **local**: solo las reglas locales, sin acceso a internet.

Las respuestas de OSV se guardan en `~/.cache/vexcore/osv/` durante 24 h. Más detalles en [`docs/osv.md`](docs/osv.md).

### Supresiones (`.vexcoreignore`)

Crea un `.vexcoreignore` en la raíz del directorio escaneado. Una entrada por línea; `#` para comentarios:

```
# Suprimir una regla en todo el proyecto
DJG001

# Suprimir archivos por ruta relativa (patrones fnmatch)
tests/*.py
*/generated/*
```

## Reglas

**74 reglas** en 11 archivos:

| Archivo | IDs | Reglas | Categoría |
|---------|-----|-------:|-----------|
| `sast/django.json` | DJG001–DJG005 | 5 | SAST Python/Django |
| `sast/js.json` | JS001–JS006 | 6 | SAST JavaScript/TypeScript (`.js`, `.jsx`, `.ts`, `.tsx`, `.html`) |
| `sast/php.json` | PHP001–PHP013 | 13 | SAST PHP |
| `sast/go.json` | GOO001–GOO005 | 5 | SAST Go |
| `sast/java.json` | JAV001–JAV005 | 5 | SAST Java |
| `sast/ruby.json` | RBY001–RBY004 | 4 | SAST Ruby |
| `secrets/generic.json` | SEC001–SEC016 | 16 | Secretos (cualquier archivo) |
| `config/env.json` | CFG001–CFG004 | 4 | Configuración `.env` |
| `config/docker.json` | CFG005–CFG007 | 3 | Configuración docker-compose |
| `config/django_settings.json` | CFG008–CFG010 | 3 | Configuración Django |
| `sca/pypi.json` | PYA001–PYA010 | 10 | SCA PyPI |

Además, el analizador AST de Python (siempre activo) detecta `eval()`, `exec()`, `os.system()`, `subprocess.call/run/Popen` y `pickle.load/loads`.

Documentación con ejemplos de código vulnerable y su corrección: [`docs/python.md`](docs/python.md) (DJG + PYA). La documentación de PHP y JS ([`docs/php.md`](docs/php.md)) está pendiente.

### Formato: SAST, secretos y configuración

```json
{
  "id": "DJG001",
  "title": "SQL crudo con interpolación",
  "severity": "high",
  "extensions": [".py"],
  "pattern": "\\.raw\\s*\\(.*(%s|%d|\\.format\\(|f['\"])"
}
```

| Campo | Descripción |
|-------|-------------|
| `id` | Identificador único: 3 letras + 3 dígitos (ej. `DJG001`). |
| `title` | Descripción corta. |
| `severity` | `critical`, `high`, `medium`, `low` o `info`. |
| `extensions` | Extensiones a las que aplica (vacío = todas). Deben estar en `scan_extensions`. |
| `pattern` | Expresión regular de Python que se evalúa línea a línea. |

### Formato: SCA

```json
{
  "id": "PYA001",
  "title": "Django < 3.2.25 — SQL injection",
  "severity": "high",
  "package": "django",
  "version_constraint": "<3.2.25"
}
```

`version_constraint` admite restricciones como `<3.2.25` o `>=1.0,<2.0`.

> Los archivos JSON inválidos o las reglas con un patrón incorrecto se omiten.

## Extensibilidad

### Plugins

Cada subdirectorio de `plugins_dir` es un plugin:

```
plugins/
└── mi_analyzer/
    ├── plugin.json      # {"id": "mi_analyzer", "module": "analyzer", "class": "Analyzer"}
    └── analyzer.py      # define una clase que implementa IAnalyzer
```

`class` es opcional (por defecto `Analyzer`). La clase debe heredar de `vexcore.ports.IAnalyzer` e implementar `analyze(file: FileInfo) -> list[Finding]`. Los plugins inválidos se omiten con un aviso.

### Uso como librería

```python
import vexcore

report = vexcore.scan("./mi_proyecto")  # config: igual que la CLI
print(report.total)
for finding in report.findings:
    print(finding.rule_id, finding.file.relative, finding.line)
```

`vexcore.scan()` ejecuta los analizadores SAST, de secretos y AST. Los de SCA, configuración y los plugins solo se ejecutan desde la CLI.

## Arquitectura

| Capa | Ubicación |
|------|-----------|
| Dominio | `vexcore/domain.py`: `Severity`, `Category`, `Rule`, `FileInfo`, `Finding`, `Report`. Sin dependencias externas. |
| Puertos | `vexcore/ports.py`: `IAnalyzer`, `IReporter`. |
| Adaptadores de entrada | CLI (`vexcore/main.py`), TUI (`vexcore/tui/`) y librería (`vexcore/__init__.py`). |
| Adaptadores de salida | Crawler (`crawler.py`), analizadores (`analyzers/`), reporters (`reporters/`), caché (`cache.py`). |
| Orquestación | `vexcore/engine.py`: analiza en paralelo, aplica supresiones y deduplica (misma línea y categoría → se conserva la mayor severidad). |

```
VexCore/
├── config.yaml                 # Configuración por defecto
├── pyproject.toml
├── docs/                       # Documentación de reglas y OSV
├── tests/
├── .github/workflows/          # CI y escaneo con Code Scanning
└── vexcore/
    ├── rules/                  # Reglas JSON (incluidas en el paquete)
    │   ├── sast/  secrets/  config/  sca/
    ├── analyzers/
    │   ├── _loader.py          # Carga de reglas JSON
    │   ├── _regex.py           # Motor regex compartido
    │   ├── sast.py  secrets.py  config.py
    │   ├── ast_analyzer.py     # Análisis AST de Python
    │   ├── sca.py              # Análisis de dependencias
    │   └── osv.py              # Cliente OSV.dev (caché + API)
    ├── reporters/              # console.py, json.py, sarif.py
    ├── tui/                    # Interfaz Textual
    ├── utils/config_loader.py  # config.yaml → AppConfig
    ├── cache.py  crawler.py  domain.py  engine.py
    ├── main.py  plugins.py  ports.py  suppressions.py
    └── __init__.py             # API de librería: vexcore.scan()
```

## Desarrollo

```bash
uv sync                 # instala dependencias, incluidas las de desarrollo
uv run pytest           # tests
uv run ruff check .     # lint
```

El CI (`.github/workflows/`) ejecuta en cada PR:

- **Lint** con ruff.
- **Tests** en Python 3.11, 3.12, 3.13 y 3.14.
- **Build del wheel** y prueba del paquete instalado desde fuera del repo.
- **Escaneo del propio repo con VexCore**, que sube el resultado a GitHub Code Scanning. El check `vexcore` falla si el PR introduce alertas nuevas; si un test necesita un secreto de ejemplo, constrúyelo de forma que la línea del código fuente no coincida con la regla.

## Dependencias

- [`PyYAML`](https://pyyaml.org/) — lectura de `config.yaml`
- [`Textual`](https://textual.textualize.io/) — interfaz TUI
- Desarrollo: `pytest`, `ruff`
