# Plan de Escalado — VexCore

## Estado actual

~2,000 líneas Python, 74 reglas JSON. SAST regex + AST (Python), secrets, SCA con OSV API, config rules. Tres reporters (consola, JSON, SARIF), paralelismo en engine y queries OSV, suppressions, deduplicación, plugin system, incremental scanning, librería Python, pre-commit hook, GitHub Action, tests básicos (10 tests).

---

## Fase 1 — Fundación [X]

Sin nuevas dependencias. Solo stdlib.

- [x] **Paralelismo en engine.py** — `concurrent.futures.ThreadPoolExecutor` en el loop de archivos
- [x] **Paralelizar OSV queries** — `ThreadPoolExecutor` en `sca.py` para HTTP requests
- [x] **Streaming en engine** — `pool.map` perezoso: findings entran al report según terminan
- [x] **Reporter JSON** — `reporters/json.py`. Flag `--output json`
- [x] **Reporter SARIF** — `reporters/sarif.py`. Formato GitHub Code Scanning
- [x] **Exit code** — `sys.exit(1)` si hay findings >= threshold. Flag `--fail-on`
- [x] **`--no-color`** flag + auto-detect `NO_COLOR` env var
- [x] **Suppressions** — `.vexcoreignore` con rule IDs o file patterns
- [x] **Tests básicos** — pytest sobre domain, regex analyzer, config loader, crawler, suppressions

Nota: el "streaming" real a reporters (IReporter incremental) no se hizo — `pool.map` ya evita acumular results de golpe; el Report sigue siendo una lista completa. Solo importa con millones de findings; rehacer la interfaz entonces.

---

## Fase 2 — Plugin system y más lenguajes [X]

- [x] **Plugin protocol** — `src/plugins.py` + `plugins/` dir + `plugin.json`
- [x] **AST-based analyzer** — `analyzers/ast_analyzer.py` con `ast` stdlib para Python
- [x] **Más reglas SAST** — Go, Java, Ruby en `rules/sast/`
- [x] **Reglas de configuración** — `rules/config/` para `.env`, `docker-compose`, `settings.py`
- [x] **Deduplicación de findings** — engine.py `_deduplicate()`: misma línea + misma categoría = solo mayor severidad

---

## Fase 3 — Integración y ecosistema [X]

- [x] **Pre-commit hook** — `pre_commit_hook.py` + `.pre-commit-hooks.yaml`
- [x] **GitHub Action** — `.github/workflows/vexcore.yml` reutilizable
- [x] **Incremental scanning** — `src/cache.py` con SHA-256 en `~/.vexcore/cache/files.json`
- [x] **Config global** — `~/.vexcore/config.yaml` como fallback
- [x] **Librería Python** — `import vexcore; report = vexcore.scan("./myproject")`

---

## Fase 4 — Premium [ ]

Solo si el proyecto crece. No hacer todavía.

- [ ] Servidor daemon con inotify/watchfiles
- [ ] Dashboard web (FastAPI)
- [ ] Rule marketplace
- [ ] Auto-fix para patrones triviales

---

## Dependencias por fase

| Fase | Nuevas dependencias |
|------|---------------------|
| 1 | Ninguna (stdlib) |
| 2 | Ninguna (stdlib) |
| 3 | Ninguna (stdlib) |
| 4 | `watchfiles`, `fastapi` + `uvicorn` |

## No hacer

- API REST/servidor hasta que 10+ personas lo usen
- Frontend web — JSON/SARIF es suficiente
- Base de datos — cache en filesystem funciona
- Interprocedural analysis — proyecto de investigación
- Auto-fix para más de 3 patrones triviales
