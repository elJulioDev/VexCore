# Integración con OSV.dev

VexCore puede consultar [OSV.dev](https://osv.dev) (Open Source Vulnerabilities)
para obtener vulnerabilidades reales de cualquier ecosistema, en lugar de
depender únicamente de reglas locales escritas a mano.

## Cómo funciona

Por cada dependencia extraída de un manifest (`requirements.txt`,
`pyproject.toml`), el SCA Analyzer consulta la API de OSV.dev:

```
POST https://api.osv.dev/v1/query
Content-Type: application/json

{
  "package": {"name": "django", "ecosystem": "PyPI"},
  "version": "3.2.20"
}
```

Respuesta:
```json
{
  "vulns": [
    {
      "id": "GHSA-xxxx",
      "summary": "SQL injection in Django",
      "severity": [{"type": "CVSS_V3", "score": "7.5"}],
      "database_specific": {"severity": "HIGH"},
      "affected": [{
        "ranges": [{
          "type": "ECOSYSTEM",
          "events": [{"introduced": "0"}, {"fixed": "3.2.25"}]
        }]
      }]
    }
  ]
}
```

## Traducción de severidad

OSV.dev no tiene un campo severity único y consistente porque los datos
provienen de múltiples fuentes. VexCore intenta varias estrategias en
orden de prioridad:

| Prioridad | Fuente | Ejemplo |
|-----------|--------|---------|
| 1 | `database_specific.severity` (GHSA) | `"HIGH"` → high |
| 2 | `severity[].score` (CVSS numérico) | `7.5` → high (>= 7.0) |
| 3 | Default | → medium |

## Caché local

Las respuestas de OSV se cachean en `~/.cache/vexcore/osv/` para evitar
repetir queries por el mismo (paquete, versión) en escaneos consecutivos.

- **TTL:** 24 horas
- **Ubicación:** `~/.cache/vexcore/osv/<hash>.json`
- **Forzar actualización:** borrar el directorio `~/.cache/vexcore/osv/`

## Modos de fuente

El SCA Analyzer soporta tres modos configurables en `config.yaml`:

```yaml
analyzers:
  sca:
    enabled: true
    source: both  # opciones: both, osv, local
```

| Modo | Comportamiento |
|------|---------------|
| `both` (default) | OSV primero. Si OSV no encuentra nada o falla la conexión, usa reglas locales |
| `osv` | Solo OSV. Ignora reglas locales completamente |
| `local` | Solo reglas locales. No intenta conexión a OSV |

## Sin internet

Si no hay conexión a internet o la API falla, el comportamiento depende
del modo:

- **both:** OSV retorna vacío → se usan reglas locales como fallback
- **osv:** OSV retorna vacío → no se reporta nada para ese paquete
- **local:** No afecta (nunca intenta conexión)

En ningún caso el escaneo se rompe por falta de red.

## Ecosistemas soportados

Actualmente solo PyPI. OSV.dev soporta múltiples ecosistemas (npm, Go,
Rust, Maven, etc.) que pueden agregarse en el futuro extendiendo el
parámetro `ecosystem` en `osv.py`.

## Costo y límites

- **Gratuito:** OSV.dev es un servicio público de Google sin costo
- **Sin API key:** No requiere registro ni autenticación
- **Sin rate limit documentado:** Protección básica contra abuso
