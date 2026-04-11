# BEST UC3M Hackathon Workspace

Monorepo del proyecto completo del hackathon "Help the Developer".

## Estructura

- `security-agent-plugin/`
  Plugin principal de JetBrains/IntelliJ/PyCharm para detección, explicación y fix de vulnerabilidades.
- `demo-vulnerable-app/`
  Aplicación Flask intencionalmente vulnerable usada para la demo en vivo.
- `koog-spike/`
  Spike aislado para validar Koog + OpenAI desde Kotlin/JVM antes de integrarlo en el plugin.
- `.claude/`
  Notas y placeholders para configuración local de asistentes. Los ajustes específicos de máquina no se versionan.
- `Help the Dev Challenge Presentation.pdf`
  Material de apoyo para la presentación.

## Setup rápido

### Plugin principal

```powershell
cd security-agent-plugin
.\gradlew.bat test
.\gradlew.bat runIde
```

### Demo vulnerable

```powershell
cd demo-vulnerable-app
py -3.11 -m venv .venv
.\.venv\Scripts\python -m pip install -r requirements.txt
```

### Koog spike

```powershell
cd koog-spike
$env:OPENAI_API_KEY="..."
.\gradlew.bat run
```

## Notas

- `semgrep` debe estar disponible en `PATH` para el flujo principal del plugin.
- Los ficheros generados localmente como `.venv/`, `build/`, `.idea/` y los reports exportados no se versionan.
