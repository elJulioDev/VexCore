# Plan de Escalado — VexCore

## Estado actual

~1,340 líneas Python, 50 reglas JSON. SAST regex por línea, secrets con patrones, SCA con OSV API. Un solo reporter (consola), sin tests, sin paralelismo, sin plugin system.

---

## Fase 1 — Fundación [ ]

Sin nuevas dependencias. Solo stdlib.

- [ ] **Paralelismo en engine.py** — `concurrent.futures.ThreadPoolExecutor` en el loop de archivos
- [ ] **Paralelizar OSV queries** — `ThreadPoolExecutor` en `sca.py` para HTTP requests
- [ ] **Streaming en engine** — yield incremental de findings en vez de lista acumulada
- [ ] **Reporter JSON** — `reporters/json.py`. Flag `--output json`
- [ ] **Reporter SARIF** — `reporters/sarif.py`. Formato GitHub Code Scanning
- [ ] **Exit code** — `sys.exit(1)` si hay findings >= threshold. Flag `--fail-on`
- [ ] **`--no-color`** flag + auto-detect `NO_COLOR` env var
- [ ] **Suppressions** — `.vexcoreignore` con rule IDs o file patterns
- [ ] **Tests básicos** — pytest sobre domain, regex analyzer, config loader, crawler

---

## Fase 2 — Plugin system y más lenguajes [ ]

- [ ] **Plugin protocol** — Directorio con `plugin.json` + módulo `IAnalyzer`
- [ ] **AST-based analyzer** — `analyzers/ast_analyzer.py` con `ast` stdlib para Python
- [ ] **Más reglas SAST** — Python, Go, Java, Ruby en `rules/sast/`
- [ ] **Reglas de configuración** — `rules/config/` para `.env`, `docker-compose`, `settings.py`
- [ ] **Deduplicación de findings** — Misma línea + misma categoría = solo mayor severidad

---

## Fase 3 — Integración y ecosistema [ ]

- [ ] **Pre-commit hook** — `pre_commit_hook.py` + config sample
- [ ] **GitHub Action** — `.github/workflows/vexcore.yml` reutilizable
- [ ] **Incremental scanning** — SHA-256 hash cache en `~/.vexcore/cache/files.json`
- [ ] **Config global** — `~/.vexcore/config.yaml` como default
- [ ] **Librería Python** — `import vexcore; report = vexcore.scan("./myproject")`

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
| 2 | `tomllib` (stdlib 3.11+) |
| 3 | `watchfiles` (opcional, solo daemon) |
| 4 | `fastapi` + `uvicorn` |

## No hacer

- API REST/servidor hasta que 10+ personas lo usen
- Frontend web — JSON/SARIF es suficiente
- Base de datos — cache en filesystem funciona
- Interprocedural analysis — proyecto de investigación
- Auto-fix para más de 3 patrones triviales
