# Reglas Python — SAST (Django) + SCA (PyPI)

## SAST — Django (DJG001–DJG005)

### DJG001 — SQL crudo con interpolación

| Campo | Valor |
|-------|-------|
| Severidad | high |
| Detecta | `Model.objects.raw()` con interpolación de strings |
| Cómo se usa | Regex busca `.raw(` seguido de `%s`, `%d`, `.format()` o f-string |

**Código vulnerable:**
```python
# Interpolación directa — vulnerable a SQL injection
User.objects.raw("SELECT * FROM users WHERE id = %s" % user_id)
User.objects.raw(f"SELECT * FROM users WHERE id = {user_id}")
```

**Código seguro:**
```python
# Pasar parámetros por separado — Django los escapa
User.objects.raw("SELECT * FROM users WHERE id = %s", [user_id])
```

### DJG002 — DEBUG activo en producción

| Campo | Valor |
|-------|-------|
| Severidad | medium |
| Detecta | `DEBUG = True` en settings.py |
| Cómo se usa | Regex busca `DEBUG = True` como línea independiente |

**Código vulnerable:**
```python
# Expone stack traces detallados a usuarios
DEBUG = True
```

**Código seguro:**
```python
DEBUG = False

# O mejor: control por variable de entorno
import os
DEBUG = os.getenv("DJANGO_DEBUG", "false").lower() == "true"
```

### DJG003 — SECRET_KEY hardcodeado

| Campo | Valor |
|-------|-------|
| Severidad | critical |
| Detecta | Asignación directa de `SECRET_KEY` con string literal |
| Cómo se usa | Regex busca `SECRET_KEY = "..."` con al menos 8 caracteres |

**Código vulnerable:**
```python
SECRET_KEY = "django-insecure-8#6^4f3@2s1a9q0w8e7r6t5y4u3i2o1p"
```

**Código seguro:**
```python
import os
SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]
```

### DJG004 — Vista exenta de CSRF

| Campo | Valor |
|-------|-------|
| Severidad | medium |
| Detecta | Decorador `@csrf_exempt` en vistas |
| Cómo se usa | Regex busca `@csrf_exempt` |

**Código vulnerable:**
```python
from django.views.decorators.csrf import csrf_exempt

@csrf_exempt
def create_user(request):
    # Sin protección CSRF — acepta POST de cualquier origen
    ...
```

**Código seguro:**
```python
# Eliminar el decorador y usar el middleware CSRF por defecto
def create_user(request):
    # Django valida el token CSRF automáticamente
    ...
```

### DJG005 — Uso de eval()

| Campo | Valor |
|-------|-------|
| Severidad | high |
| Detecta | Llamadas a `eval()` |
| Cómo se usa | Regex busca `eval(` con espacio opcional |

**Código vulnerable:**
```python
resultado = eval(input("Ingresa una expresión: "))
# El usuario puede ejecutar código arbitrario:
# > __import__('os').system('rm -rf /')
```

**Código seguro:**
```python
# Usar alternativas seguras
import ast
resultado = ast.literal_eval(entrada)  # solo evalúa literales Python
```

---

## SCA — PyPI (PYA001–PYA010)

Las reglas SCA no buscan patrones en el código. Analizan archivos
manifest (`requirements.txt`, `pyproject.toml`) y comparan la versión
de cada dependencia contra una restricción. Si la versión instalada
cae dentro del rango vulnerable, se reporta.

### PYA001 — Django < 3.2.25

| Campo | Valor |
|-------|-------|
| Severidad | high |
| Paquete | django |
| Versión vulnerable | < 3.2.25 |
| Versión segura | 3.2.25+ |

**Ejemplo detectado:** `django==3.2.20`
**Solución:** `django==3.2.25`

### PYA002 — Django < 4.2.16

| Campo | Valor |
|-------|-------|
| Severidad | high |
| Paquete | django |
| Versión vulnerable | < 4.2.16 |
| Versión segura | 4.2.16+ |

**Ejemplo detectado:** `django==4.2.0`
**Solución:** `django==4.2.16`

### PYA003 — Requests < 2.32.0

| Campo | Valor |
|-------|-------|
| Severidad | high |
| Paquete | requests |
| Versión vulnerable | < 2.32.0 |
| Versión segura | 2.32.0+ |

**Ejemplo detectado:** `requests==2.31.0`
**Solución:** `requests==2.32.0`

### PYA004 — Flask < 3.1.0

| Campo | Valor |
|-------|-------|
| Severidad | medium |
| Paquete | flask |
| Versión vulnerable | < 3.1.0 |
| Versión segura | 3.1.0+ |

**Ejemplo detectado:** `flask==3.0.0`
**Solución:** `flask==3.1.0`

### PYA005 — Urllib3 < 2.2.2

| Campo | Valor |
|-------|-------|
| Severidad | high |
| Paquete | urllib3 |
| Versión vulnerable | < 2.2.2 |
| Versión segura | 2.2.2+ |

**Ejemplo detectado:** `urllib3==2.0.0`
**Solución:** `urllib3==2.2.2`

### PYA006 — Jinja2 < 3.1.5

| Campo | Valor |
|-------|-------|
| Severidad | medium |
| Paquete | jinja2 |
| Versión vulnerable | < 3.1.5 |
| Versión segura | 3.1.5+ |

**Ejemplo detectado:** `jinja2==3.1.0`
**Solución:** `jinja2==3.1.5`

### PYA007 — Pillow < 10.4.0

| Campo | Valor |
|-------|-------|
| Severidad | high |
| Paquete | pillow |
| Versión vulnerable | < 10.4.0 |
| Versión segura | 10.4.0+ |

**Ejemplo detectado:** `pillow==10.0.0`
**Solución:** `pillow==10.4.0`

### PYA008 — FastAPI < 0.115.6

| Campo | Valor |
|-------|-------|
| Severidad | high |
| Paquete | fastapi |
| Versión vulnerable | < 0.115.6 |
| Versión segura | 0.115.6+ |

**Ejemplo detectado:** `fastapi==0.100.0`
**Solución:** `fastapi==0.115.6`

### PYA009 — pyyaml < 6.0.2

| Campo | Valor |
|-------|-------|
| Severidad | critical |
| Paquete | pyyaml |
| Versión vulnerable | < 6.0.2 |
| Versión segura | 6.0.2+ |

Esta vulnerabilidad afecta directamente a VexCore porque PyYAML es
una dependencia del proyecto. `yaml.load()` sin `Loader` puede ejecutar
código arbitrario.

**Ejemplo detectado:** `pyyaml==6.0.1`
**Solución:** `pyyaml==6.0.2`

### PYA010 — cryptography < 43.0.1

| Campo | Valor |
|-------|-------|
| Severidad | medium |
| Paquete | cryptography |
| Versión vulnerable | < 43.0.1 |
| Versión segura | 43.0.1+ |

**Ejemplo detectado:** `cryptography==42.0.0`
**Solución:** `cryptography==43.0.1`
