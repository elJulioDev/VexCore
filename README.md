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
  - **Django (Python):** SQL crudo, `eval()`, `DEBUG=True`, `SECRET_KEY` expuestas.
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
    enabled: false
    rules_path: rules/sca

output:
  severity_threshold: low
```

## Estructura del Proyecto

```text
vexcore/
├── config.yaml             # Configuración principal
├── pyproject.toml          # Metadatos y dependencias
├── rules/                  # Reglas en formato JSON
│   ├── sast/               # django.json, js.json, php.json
│   ├── secrets/            # generic.json (14 patrones)
│   └── sca/                # pypi.json (10 reglas SCA)
├── src/
│   ├── analyzers/          # Motores de análisis
│   │   ├── _base.py        # Engine regex compartido
│   │   ├── sast.py         # Adaptador SAST
│   │   ├── secrets.py      # Adaptador de secretos
│   │   └── sca.py          # Adaptador SCA (PyPI)
│   ├── reporters/          # Salida de resultados
│   │   └── console.py      # Reporte con colores ANSI
│   ├── utils/              # Utilidades
│   │   └── config_loader.py # Carga de config.yaml
│   ├── crawler.py          # Recorrido del sistema de archivos
│   ├── domain.py           # Entidades de negocio
│   ├── engine.py           # Orquestador
│   ├── main.py             # Punto de entrada CLI
│   └── ports.py            # Puertos (IAnalyzer, IReporter)
└── AGENTS.md               # Guía para asistentes IA
```

## Dependencias

- `PyYAML >= 6.0.3` — carga de configuración YAML
