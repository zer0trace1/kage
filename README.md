# KAGE

**Trace what hides in the shadows.**

KAGE es una herramienta CLI de ciberinteligencia orientada al enriquecimiento de indicadores.  
En su versión actual, permite analizar direcciones IP y obtener contexto de red, geolocalización y señales de reputación a partir de fuentes OSINT/CTI públicas.

## Características

- Enriquecimiento de direcciones IP
- Contexto de red: ISP, AS, organización, hosting, proxy, etc.
- Geolocalización básica
- Integración opcional con AbuseIPDB para reputación
- Clasificación simple del indicador:
  - `clean`
  - `suspicious`
  - `malicious`
  - `unknown`

## Fuentes utilizadas

- **ip-api**: contexto de red y geolocalización
- **AbuseIPDB**: reputación y señales de abuso

## Requisitos

- Python 3.10+
- Entorno virtual recomendado

## Instalación

Clona el repositorio:

```bash
git clone git@github.com:TU_USUARIO/kage.git
cd kage
```

Crea y activa un entorno virtual:

### Linux / macOS
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### Windows PowerShell
```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

Instala las dependencias:

```bash
pip install -r requirements.txt
```

## Configuración

KAGE puede funcionar sin clave de API para AbuseIPDB, pero en ese caso omitirá la parte de reputación avanzada.

Crea un archivo `.env` en la raíz del proyecto:

```env
ABUSEIPDB_API_KEY=tu_api_key_aqui
```

También puedes partir del archivo de ejemplo:

```bash
cp .env.example .env
```

## Uso

### Mostrar versión
```bash
python kage.py version
```

### Analizar una IP
```bash
python kage.py ip 8.8.8.8
```

## Ejemplo de salida

```text
KAGE → analizando 8.8.8.8

Clasificación: Clean
Motivo: Sin señales relevantes o infraestructura pública conocida
País: United States
ISP: Google LLC
AS: AS15169 Google LLC
```

## Funcionamiento de la clasificación

KAGE aplica una heurística sencilla basada en:

- tipo de dirección IP
- contexto de infraestructura
- score de abuso
- número de reportes
- señales como TOR, proxy o infraestructura pública conocida

Esta clasificación es **orientativa** y no debe considerarse una conclusión definitiva por sí sola.

## Limitaciones

- Actualmente solo soporta análisis de **IP**
- La clasificación se basa en heurísticas simples
- La precisión depende de la calidad y actualidad de las fuentes consultadas
- `ip-api` en su versión gratuita tiene limitaciones de uso

## Roadmap

Versiones futuras de KAGE podrían incluir:

- análisis de dominios
- análisis de URLs
- análisis de hashes
- salida en formato JSON
- integración con más fuentes OSINT/CTI
- exportación de resultados

## Estructura actual

```text
kage/
├── kage.py
├── requirements.txt
├── .env.example
├── .gitignore
└── README.md
```

## Licencia

MIT License.

## Autor

**Pablo Infante**  
Máster en Ciberseguridad y Ciberinteligencia
