"""plugins.py — Carga analizadores desde el directorio de plugins.

Cada plugin es un directorio con:
  plugin.json  → {"id": str, "module": str, "class": str (opcional)}
  {module}.py  → clase que implementa IAnalyzer

Ejemplo:
  plugins/mi_analyzer/plugin.json
  plugins/mi_analyzer/analyzer.py
"""

from __future__ import annotations
import importlib.util
import json
import logging
from pathlib import Path
from .ports import IAnalyzer

logger = logging.getLogger(__name__)

_REQUIRED_KEYS = {"id", "module"}


def load_plugins(plugins_dir: Path) -> list[IAnalyzer]:
    """Descubre y carga plugins desde plugins_dir.

    Retorna solo los analyzers cuyo plugin.json es válido y cuyo
    módulo se puede importar. Plugins malformados se saltan con warning.
    """
    if not plugins_dir.is_dir():
        return []

    analyzers: list[IAnalyzer] = []
    for plugin_dir in sorted(plugins_dir.iterdir()):
        if not plugin_dir.is_dir():
            continue
        analyzer = _load_one(plugin_dir)
        if analyzer is not None:
            analyzers.append(analyzer)
    return analyzers


def _load_one(plugin_dir: Path) -> IAnalyzer | None:
    manifest_path = plugin_dir / "plugin.json"
    if not manifest_path.exists():
        logger.warning("Plugin %s: sin plugin.json, se omite", plugin_dir.name)
        return None

    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        logger.warning("Plugin %s: plugin.json inválido (%s)", plugin_dir.name, e)
        return None

    if not _REQUIRED_KEYS.issubset(manifest):
        logger.warning("Plugin %s: plugin.json falta %s", plugin_dir.name, _REQUIRED_KEYS - manifest.keys())
        return None

    module_name = manifest["module"]
    class_name = manifest.get("class", "Analyzer")
    module_path = plugin_dir / f"{module_name}.py"

    if not module_path.exists():
        logger.warning("Plugin %s: módulo %s no encontrado", plugin_dir.name, module_path)
        return None

    try:
        spec = importlib.util.spec_from_file_location(f"vexcore_plugin_{manifest['id']}", module_path)
        if spec is None or spec.loader is None:
            return None
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
    except Exception as e:
        logger.warning("Plugin %s: error importando (%s)", plugin_dir.name, e)
        return None

    cls = getattr(mod, class_name, None)
    if cls is None:
        logger.warning("Plugin %s: clase '%s' no encontrada en módulo", plugin_dir.name, class_name)
        return None

    try:
        instance = cls()
    except Exception as e:
        logger.warning("Plugin %s: error instanciando (%s)", plugin_dir.name, e)
        return None

    if not isinstance(instance, IAnalyzer):
        logger.warning("Plugin %s: %s no implementa IAnalyzer", plugin_dir.name, class_name)
        return None

    return instance
