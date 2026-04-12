# BEST UC3M Hackathon 2026

Monorepo oficial del proyecto desarrollado para el reto **"Help the Developer"** de BEST UC3M. El objetivo del repositorio es validar una experiencia asistida dentro del IDE para **detectar, contextualizar, priorizar y remediar vulnerabilidades de seguridad** en proyectos de software sin obligar al desarrollador a salir de su flujo de trabajo.

El repositorio reúne tres piezas complementarias:

- un **plugin para IntelliJ IDEA / PyCharm** que ejecuta análisis SAST, muestra findings en el IDE, aplica enriquecimiento con agentes y propone fixes;
- una **aplicación Flask intencionalmente vulnerable** utilizada como fixture de demo y como base de pruebas funcionales;
- un **spike aislado de Koog** para validar la integración Kotlin + OpenAI antes de incorporar esa capacidad al plugin principal.

## Tabla de contenidos

1. [Resumen Ejecutivo](#resumen-ejecutivo)
2. [Objetivos del proyecto](#objetivos-del-proyecto)
3. [Arquitectura del monorepo](#arquitectura-del-monorepo)
4. [Componente 1: Security Agent Plugin](#componente-1-security-agent-plugin)
5. [Componente 2: Demo Vulnerable App](#componente-2-demo-vulnerable-app)
6. [Componente 3: Koog Spike](#componente-3-koog-spike)
7. [Flujo funcional end-to-end](#flujo-funcional-end-to-end)
8. [Modelo de clasificación y validación](#modelo-de-clasificación-y-validación)
9. [Requisitos del entorno](#requisitos-del-entorno)
10. [Instalación y ejecución local](#instalación-y-ejecución-local)
11. [Verificación y pruebas](#verificación-y-pruebas)
12. [Estado actual y limitaciones](#estado-actual-y-limitaciones)
13. [Estructura del repositorio](#estructura-del-repositorio)
14. [Convenciones y artefactos generados](#convenciones-y-artefactos-generados)
15. [Próximos pasos recomendados](#próximos-pasos-recomendados)

## Resumen Ejecutivo

El proyecto implementa una arquitectura híbrida para seguridad en el IDE:

- **detección determinista** mediante `Semgrep`;
- **normalización y representación interna** de findings en Kotlin;
- **enriquecimiento agentic** para validar findings, explicar impacto, describir la cadena de explotación y proponer remediaciones;
- **integración nativa en JetBrains IDEs** con tool window, inspecciones, quick-fixes y export de reportes.

La aproximación no intenta reemplazar completamente el análisis estático clásico por IA. En su estado actual, el análisis determinista detecta los hallazgos base y la capa agentic aporta contexto adicional y apoyo a la remediación.

## Objetivos del proyecto

Los objetivos funcionales del repositorio son los siguientes:

- detectar vulnerabilidades frecuentes en proyectos Python desde el IDE;
- reducir fricción entre detección, comprensión y corrección;
- disminuir falsos positivos percibidos mediante validación contextual;
- ofrecer explicaciones legibles para desarrolladores no especialistas en seguridad;
- generar propuestas de fix con vista previa antes de aplicar cambios;
- servir como base demostrable y extensible para futuras fases del producto.

## Arquitectura del monorepo

El monorepo está organizado como una solución multi-componente:

```text
best-hackathon-2026/
├── security-agent-plugin/   Plugin JetBrains principal
├── demo-vulnerable-app/     Aplicación Flask vulnerable para demo
├── koog-spike/              Spike aislado de Koog + OpenAI
├── Help the Dev Challenge Presentation.pdf
└── README.md
```

Cada carpeta tiene un propósito distinto:

- `security-agent-plugin/` contiene el producto principal.
- `demo-vulnerable-app/` contiene vulnerabilidades controladas que permiten validar el flujo del plugin.
- `koog-spike/` reduce el riesgo técnico de la integración con Koog sin bloquear el plugin principal.

## Componente 1: Security Agent Plugin

`security-agent-plugin/` es el núcleo del proyecto. Se trata de un plugin para la plataforma JetBrains desarrollado en Kotlin sobre Gradle.

### Propósito

Su finalidad es permitir que un desarrollador:

- lance un escaneo SAST desde el menú del IDE;
- vea findings agrupados por severidad;
- navegue al código afectado;
- reciba validación, explicación y guía de remediación;
- aplique un quick-fix cuando exista un parche utilizable;
- exporte un reporte técnico del escaneo.

### Capacidades principales implementadas

En el estado actual del repositorio, el plugin incluye:

- acción `Scan Project for Security Issues`;
- ejecución de `Semgrep` sobre archivos Python del proyecto;
- parseo de SARIF a un modelo tipado `Finding`;
- tool window con lista de findings y panel de detalle;
- settings para API key, modelo y base URL de OpenAI;
- almacenamiento seguro de credenciales mediante Password Safe;
- cliente OpenAI reutilizable con chat, respuestas estructuradas y streaming;
- capa agentic para triage, validación, explicación y generación de fixes;
- quick-fix con vista previa y comprobación de conflicto sobre el contenido original;
- export de reportes en Markdown y HTML.

### Arquitectura interna del plugin

A nivel conceptual, el plugin está dividido en varios subsistemas:

- **SAST**
  - `SemgrepRunner`
  - `SarifParser`
  - modelos intermedios de findings
- **Orquestación**
  - `SecurityScanService`
  - estado de escaneo y publicación de eventos
- **Agentes**
  - `AgentCoordinator`
  - `TriagerAgent`
  - `ValidatorAgent`
  - `ExplainerAgent`
  - `FixGeneratorAgent`
- **OpenAI / Koog**
  - `OpenAIClient`
  - `KoogAgentRunner`
  - resolución de modelos
- **IDE UX**
  - tool window
  - inspecciones
  - quick fixes
  - chat contextual
  - export de reportes

### Flujo interno del plugin

El flujo simplificado es este:

1. El usuario lanza un escaneo desde el IDE.
2. `SecurityScanService` recopila los archivos Python del proyecto.
3. `SemgrepRunner` ejecuta `semgrep scan --config p/security-audit ...`.
4. `SarifParser` transforma el SARIF en objetos `Finding`.
5. El estado del escaneo se publica al tool window y a las inspecciones.
6. Si hay credenciales configuradas, `AgentCoordinator` enriquece los findings.
7. El usuario puede revisar explicaciones, hablar con el agente o aplicar fixes.
8. El plugin puede exportar un reporte consolidado del análisis.

## Componente 2: Demo Vulnerable App

`demo-vulnerable-app/` es una aplicación Flask intencionalmente insegura. No es un ejemplo de buenas prácticas, sino un fixture de demostración controlado para forzar findings reconocibles.

### Propósito

Su función dentro del monorepo es doble:

- permitir demos end-to-end del plugin en un proyecto pequeño y comprensible;
- servir como base de pruebas manuales y de fixtures para el análisis SAST.

### Vulnerabilidades modeladas

La app contiene ejemplos deliberados de:

- `CWE-798` hardcoded credentials / secrets;
- `CWE-89` SQL injection;
- `CWE-78` command injection;
- `CWE-502` insecure deserialization;
- `CWE-22` path traversal;
- `CWE-918` SSRF;
- `CWE-327` weak cryptography;
- `CWE-79` server-side XSS.

### Consideraciones

- La aplicación **no debe desplegarse** en ningún entorno real.
- Su diseño busca claridad didáctica, no realismo productivo.
- Los findings que aparecen en el plugin se entienden mejor cuando el proyecto abierto en el IDE es esta aplicación.

## Componente 3: Koog Spike

`koog-spike/` es un módulo Kotlin/JVM aislado cuyo objetivo es demostrar que Koog puede comunicarse con OpenAI y ejecutar un agente simple desde código Kotlin.

### Por qué existe

Separar este spike del plugin principal permite:

- validar la viabilidad técnica de Koog sin romper el baseline del plugin;
- aislar problemas de runtime o compatibilidad;
- iterar rápido sobre prompts y modelos sin afectar a la integración IDE.

### Qué prueba

Actualmente el spike valida:

- lectura de `OPENAI_API_KEY` desde entorno;
- creación de un `AIAgent`;
- envío de un finding de ejemplo;
- recepción de una respuesta estructurada desde el modelo.

## Flujo funcional end-to-end

El flujo completo del proyecto puede resumirse así:

1. El desarrollador abre `demo-vulnerable-app/` en PyCharm o IntelliJ con soporte Python.
2. Ejecuta `Tools | Scan Project for Security Issues`.
3. El plugin lanza Semgrep y obtiene findings.
4. Cada finding recibe:
   - severidad base,
   - localización,
   - mensaje,
   - CWE asociado cuando está disponible.
5. Si la configuración OpenAI está disponible, el sistema agentic:
   - valida el finding,
   - estima confianza,
   - aporta explicación,
   - propone remediación.
6. El usuario revisa el detalle en el tool window.
7. Si existe parche aplicable, puede usar el quick-fix.
8. El proyecto puede reescanearse o exportarse como reporte.

## Modelo de clasificación y validación

El repositorio distingue dos conceptos que conviene no mezclar:

### 1. Severidad

La severidad representa la **gravedad potencial** del problema:

- `Critical`
- `High`
- `Medium`
- `Low`
- `Info`
- `Unknown`

En el estado actual, la severidad se calcula en la capa determinista a partir de:

- el `level` que viene en SARIF;
- el `ruleId`;
- los `CWE` asociados al hallazgo;
- una política interna de normalización definida en el plugin.

### 2. Estado de validación

La validación representa lo que la capa agentic opina sobre el hallazgo en ese contexto:

- `Pending`
- `Confirmed`
- `Needs Review`
- `Dismissed`
- `Error`

Esta separación permite expresar situaciones como:

- un finding de impacto potencial alto pero dudoso en ese flujo concreto;
- un finding moderado, pero claramente confirmado;
- un finding descartado tras revisión contextual por el agente.

## Requisitos del entorno

Para trabajar con el repositorio completo se recomienda:

- Windows 11 o entorno compatible con Gradle y JetBrains IDE;
- JDK 17 o superior;
- Python 3.11 para la demo vulnerable;
- `semgrep` disponible en `PATH`;
- una API key válida de OpenAI para el enriquecimiento agentic;
- IntelliJ IDEA 2025.2.x o compatible con la configuración del plugin.

## Instalación y ejecución local

### Plugin principal

```powershell
cd security-agent-plugin
.\gradlew.bat test
.\gradlew.bat runIde
```

Una vez abierto el IDE sandbox:

1. abre `demo-vulnerable-app/` como proyecto;
2. ve a `Settings | Tools | Security Agent`;
3. configura API key, modelo y base URL si quieres usar enriquecimiento agentic;
4. ejecuta `Tools | Scan Project for Security Issues`.

### Demo vulnerable

```powershell
cd demo-vulnerable-app
py -3.11 -m venv .venv
.\.venv\Scripts\python -m pip install -r requirements.txt
.\.venv\Scripts\python app.py
```

### Koog spike

```powershell
cd koog-spike
$env:OPENAI_API_KEY="..."
.\gradlew.bat run
```

## Verificación y pruebas

### Verificación del plugin

Desde `security-agent-plugin/`:

```powershell
.\gradlew.bat test
.\gradlew.bat buildPlugin
```

La suite actual cubre, entre otros:

- parseo de SARIF;
- cliente OpenAI;
- extracción de contexto;
- aplicación de patches;
- generación de reportes;
- filtrado de archivos a escanear.

### Verificación de la fixture SAST

Desde la raíz del repositorio:

```powershell
semgrep scan --json --config p/security-audit demo-vulnerable-app/ > findings-semgrep.json
```

El comando debe producir varios hallazgos sobre `demo-vulnerable-app/app.py`.

## Estado actual y limitaciones

El proyecto ya demuestra un flujo funcional completo, pero todavía debe entenderse como una base de hackathon / MVP avanzado, no como una plataforma de AppSec de producción.

### Estado actual

- el análisis base está centrado en Python;
- el motor de detección integrado es `Semgrep`;
- la experiencia agentic está disponible cuando existe configuración OpenAI;
- el plugin ya puede generar reportes y aplicar determinados fixes.

### Limitaciones conocidas

- dependencia actual de `Semgrep` como fuente principal de findings;
- necesidad de tener `semgrep` instalado en `PATH`;
- cobertura de lenguaje limitada principalmente a Python;
- clasificación de severidad basada en reglas internas y no en un modelo formal tipo CVSS;
- el enriquecimiento agentic puede fallar sin impedir que los findings base sigan visibles;
- la calidad de remediación depende del contexto local disponible y del modelo configurado.

## Estructura del repositorio

```text
best-hackathon-2026/
├── demo-vulnerable-app/
│   ├── README.md
│   ├── app.py
│   └── requirements.txt
├── koog-spike/
│   ├── build.gradle.kts
│   ├── gradlew
│   ├── gradlew.bat
│   ├── settings.gradle.kts
│   └── src/main/kotlin/com/hackathon/koogspike/Main.kt
├── security-agent-plugin/
│   ├── README.md
│   ├── build.gradle.kts
│   ├── gradle.properties
│   ├── settings.gradle.kts
│   └── src/
│       ├── main/kotlin/com/hackathon/securityagent/
│       ├── main/resources/
│       └── test/kotlin/com/hackathon/securityagent/
├── Help the Dev Challenge Presentation.pdf
└── README.md
```

## Convenciones y artefactos generados

No se versionan artefactos locales o generados durante desarrollo, entre ellos:

- `.venv/`
- `.gradle-user/`
- `build/`
- `bin/`
- `.idea/`
- `security-report.md`
- `security-report.html`

Además:

- las credenciales no deben escribirse en el código fuente;
- la API key del plugin se almacena mediante Password Safe;
- la app vulnerable debe tratarse exclusivamente como fixture de demostración.

## Próximos pasos recomendados

Para llevar el proyecto a un nivel más profesional, las siguientes líneas de trabajo tendrían mayor impacto:

- incorporar motores adicionales de análisis además de Semgrep;
- formalizar una política de severidad más estable y documentada;
- distinguir de forma explícita entre severidad base y severidad validada;
- añadir pruebas de integración end-to-end del flujo completo del plugin;
- extender cobertura a más lenguajes;
- añadir revalidación automática post-fix;
- medir calidad real del sistema en falsos positivos, falsos negativos y latencia.

## Licencia y uso

Salvo que se indique lo contrario en submódulos concretos, este repositorio debe entenderse como material de desarrollo para hackathon y demostración técnica. Antes de cualquier publicación externa, conviene revisar licencias, branding, metadatos del plugin y repositorio de destino.
