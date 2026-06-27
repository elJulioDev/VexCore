# VexCore

Escáner estático de seguridad (SAST), detección de secretos y análisis de
dependencias (SCA), diseñado bajo los principios de **Arquitectura Hexagonal**
(Puertos y Adaptadores).

VexCore es una herramienta modular, extensible y de alto rendimiento que no
está fuertemente acoplada a sus interfaces de entrada ni a sus motores de
análisis. Actualmente incluye soporte para proyectos en Django, JavaScript,
PHP, y detección de dependencias Python con versiones vulnerables.

## Características Principales

- **Arquitectura Hexagonal (Ports & Adapters):** Lógica de dominio pura
  (`domain.py`) aislada de detalles de infraestructura.
- **Análisis SAST:** Evaluador basado en reglas regex definidas en JSON.
- **Análisis SCA:** Detección de dependencias Python con versiones vulnerables
  mediante comparación semántica de versiones.
- **Detección de Secretos:** 14 patrones globales (AWS keys, GitHub tokens,
  Slack webhooks, JWT secrets, Stripe, etc.).
- **Soporte Multi-Lenguaje:**
  - **Python/Django:** SQL crudo, `eval()`, `DEBUG=True`, `SECRET_KEY` expuestas.
  - **JavaScript/React:** `dangerouslySetInnerHTML`, inyecciones al DOM,
    credenciales hardcodeadas.
  - **PHP:** LFI/RFI, inyección de comandos, SQLi por concatenación,
    hashing débil.
- **Crawler Eficiente (Lazy Evaluation):** Recorrido rápido de directorios
  omitiendo carpetas innecesarias (`node_modules`, `.git`, `venv`) con
  validación por tamaño y extensión.

## Arquitectura del Sistema

El proyecto sigue una arquitectura hexagonal con separación clara de
responsabilidades:

- **Dominio (`src/domain.py`):** Entidades `FileInfo`, `Finding`, `Report`.
  Cero dependencias externas.
- **Puertos (`src/ports.py`):** Interfaces abstractas `IAnalyzer` e `IReporter`.
- **Adaptadores:**
  - *Primarios (Driving):* CLI implementado en `src/main.py`.
  - *Secundarios (Driven):* Crawler (`src/crawler.py`), Analizadores
    (`src/analyzers/`), Reporter (`src/reporters/console.py`).

## Requisitos

- Python >= 3.11
- Gestor de paquetes: `uv` (recomendado) o `pip`.

## Instalación

```bash
git clone https://github.com/elJulioDev/VexCore.git
cd vexcore
uv sync
```

## Uso

```bash
# Escaneo básico de un directorio
vexcore ./mi_proyecto

# Filtrar por severidad mínima (critical, high, medium, low, info)
vexcore ./mi_proyecto --severity high

# Usar un archivo de configuración personalizado
vexcore ./mi_proyecto -c ./custom_config.yaml
```

### Configuración (`config.yaml`)

```yaml
crawler:
  ignore_dirs:
    - .git
    - node_modules
    - venv
  scan_extensions:
    - .py
    - .php
    - .js
    - .tsx
  max_file_size_mb: 5

analyzers:
  sast:
    enabled: true
    rules_path: rules/sast
  secrets:
    enabled: true
    rules_path: rules/secrets
  sca:
    enabled: false       # Cambiar a true para activar SCA
    rules_path: rules/sca

output:
  severity_threshold: low
```

El análisis SCA está deshabilitado por defecto. Para activarlo, cambia
`sca.enabled: false` a `sca.enabled: true` en `config.yaml`. Así se
escanearán los archivos `requirements.txt` y `pyproject.toml` en busca
de dependencias con versiones vulnerables.

## Reglas

### Formato de reglas SAST y Secrets

```json
{
  "id": "DJG001",
  "title": "SQL crudo con interpolación",
  "severity": "high",
  "extensions": [".py"],
  "pattern": "\\\\.raw\\\\s*\\\\(.*(%s|%d|\\\\.format\\\\(|f['\\\"])"
}
```

| Campo | Descripción |
|-------|-------------|
| `id` | Identificador único (prefijo por lenguaje) |
| `title` | Descripción corta de la vulnerabilidad |
| `severity` | critical, high, medium, low, info |
| `extensions` | Extensiones donde aplica (vacío = todos los archivos) |
| `pattern` | Expresión regular Python a buscar en cada línea |

### Formato de reglas SCA

```json
{
  "id": "PYA001",
  "title": "Django < 3.2.25 — SQL injection",
  "severity": "high",
  "package": "django",
  "version_constraint": "<3.2.25"
}
```

A diferencia de SAST, SCA no busca patrones en el código sino que
compara la **versión** de cada dependencia extraída del manifest contra
una restricción semántica (`<3.2.25`, `>=1.0,<2.0`, etc.).

### Reglas disponibles

| Archivo | ID | Cantidad | Categoría |
|---------|----|----------|-----------|
| `rules/sast/django.json` | DJG001–005 | 5 | SAST Python/Django |
| `rules/sast/php.json` | PHP001–007 | 7 | SAST PHP |
| `rules/sast/js.json` | JS001–006 | 6 | SAST JavaScript/React |
| `rules/secrets/generic.json` | SEC001–014 | 14 | Secretos (agnóstico) |
| `rules/sca/pypi.json` | PYA001–010 | 10 | SCA PyPI |

Ver documentación detallada con ejemplos de código vulnerable y cómo
corregirlo en:

- [`docs/python.md`](docs/python.md) — reglas Python (DJG + PYA)
- [`docs/php.md`](docs/php.md) — reglas PHP y JS (para tu compañero)

## Estructura del Proyecto

```
vexcore/
├── config.yaml             # Configuración principal
├── pyproject.toml          # Metadatos y dependencias
├── docs/                   # Documentación detallada de reglas
│   ├── python.md           #   Reglas Python (SAST + SCA)
│   └── php.md              #   Reglas PHP y JS
├── rules/                  # Reglas en formato JSON
│   ├── sast/               #   django.json, js.json, php.json
│   ├── secrets/            #   generic.json (14 patrones)
│   └── sca/                #   pypi.json (10 reglas SCA)
└── src/
    ├── analyzers/          # Motores de análisis
    │   ├── _base.py        #   Engine regex compartido
    │   ├── sast.py         #   Adaptador SAST
    │   ├── secrets.py      #   Adaptador de secretos
    │   └── sca.py          #   Adaptador SCA (PyPI)
    ├── reporters/          # Salida de resultados
    │   └── console.py      #   Reporte con colores ANSI
    ├── utils/              # Utilidades
    │   └── config_loader.py#   Carga de config.yaml
    ├── crawler.py          # Recorrido del sistema de archivos
    ├── domain.py           # Entidades de negocio
    ├── engine.py           # Orquestador
    ├── main.py             # Punto de entrada CLI
    └── ports.py            # Puertos (IAnalyzer, IReporter)
```

## Dependencias

- `PyYAML >= 6.0.3` — carga de configuración YAML
