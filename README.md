# VexCore

Escáner estático de seguridad (SAST) y de detección de secretos, diseñado bajo los principios de **Arquitectura Hexagonal** (Puertos y Adaptadores).

VexCore es una herramienta modular, extensible y de alto rendimiento que no está fuertemente acoplada a sus interfaces de entrada (CLI/TUI) ni a sus motores de análisis. Actualmente incluye soporte demostrativo para proyectos en Django, JavaScript (incluyendo React) y PHP, además de detección de credenciales genéricas.

## Características Principales

- **Arquitectura Hexagonal (Ports & Adapters):** Lógica de dominio pura (`domain.py`) aislada de detalles de infraestructura, lectura de archivos o interfaces de usuario.
- **Análisis SAST y Secretos:** Evaluador basado en reglas modulares definidas en JSON.
- **Soporte Multi-Lenguaje:** - **Django (Python):** Detección de SQL crudo, `eval()`, `DEBUG=True`, `SECRET_KEY` expuestas.
  - **JavaScript/React:** Detección de `dangerouslySetInnerHTML`, inyecciones al DOM, credenciales hardcodeadas.
  - **PHP:** Prevención de LFI/RFI, inyección de comandos OS, SQLi por concatenación, hashing débil.
  - **Secretos (Agnóstico):** Detección de AWS Keys, JWT secrets, Webhooks de Slack, tokens de GitHub, etc.
- **Crawler Eficiente (Lazy Evaluation):** Recorrido rápido de directorios omitiendo carpetas inútiles (`node_modules`, `.git`, `venv`) y validación por tamaño y extensión.

## Arquitectura del Sistema

El proyecto respeta la siguiente separación de responsabilidades:
- **Dominio (`src/domain.py`):** Entidades como `FileInfo`, `Finding`, `Report`. Cero dependencias externas.
- **Puertos (`src/ports.py`):** Interfaces abstractas `IAnalyzer` y `IReporter`.
- **Adaptadores:** - *Primarios (Driving):* CLI implementado en `src/main.py`.
  - *Secundarios (Driven):* Crawler de sistema de archivos (`src/crawler.py`), Adaptadores de reglas regex (`src/analyzers/`), y Salida a consola con colores (`src/reporters/console.py`).

## Requisitos

- Python >= 3.11
- Gestor de paquetes: `uv` (recomendado) o `pip`.

## Instalación

1. Clona el repositorio:

```bash
git clone https://github.com/elJulioDev/VexCore.git
cd vexcore
```

2. Instala el proyecto y sus dependencias (usa `uv` dada la presencia de `uv.lock`, o `pip` estándar):
```bash
# Usando uv (Recomendado)
uv sync
# O usando pip (Modo editable)
pip install -e .

```

## Uso

Una vez instalado, el ejecutable `vexcore` estará disponible en tu entorno.

```bash
# Escaneo básico de un directorio
vexcore ./mi_proyecto

# Filtrar resultados por nivel de severidad (ej. solo high o critical)
vexcore ./mi_proyecto --severity high

# Usar un archivo de configuración personalizado
vexcore ./mi_proyecto -c ./custom_config.yaml

```

### Configuración (`config.yaml`)

VexCore es altamente configurable mediante su archivo `config.yaml`, permitiendo ajustar las extensiones que se escanean, directorios a ignorar y habilitar/deshabilitar módulos de análisis completos:

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

output:
  severity_threshold: low

```

## Estructura del Proyecto

```text
vexcore/
├── config.yaml             # Configuración principal
├── pyproject.toml          # Metadatos del proyecto y dependencias
├── rules/                  # Reglas en formato JSON
│   ├── sast/               # (django.json, js.json, php.json)
│   └── secrets/            # (generic.json)
└── src/
    ├── analyzers/          # Adaptadores Secundarios (Motores Regex SAST/Secrets)
    ├── reporters/          # Adaptadores Secundarios (Salida por consola)
    ├── utils/              # Funciones transversales (ej. carga de config)
    ├── crawler.py          # Adaptador de FileSystem
    ├── domain.py           # Core: Entidades de Negocio Puras
    ├── engine.py           # Orquestador del crawler y analyzers
    ├── main.py             # Adaptador Primario (Punto de entrada CLI)
    └── ports.py            # Puertos: IAnalyzer, IReporter

```