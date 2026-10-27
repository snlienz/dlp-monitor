# DLP Monitor

A user-mode **endpoint data loss prevention agent** for Windows, in C++20 and Win32:

* **Windows service** (`DlpAgent.exe`) that consumes **ETW** kernel events (process, file
  and network), correlates file writes to removable media, scans the content and evaluates
  a JSON **DLP policy** (credit cards, Taiwan national IDs, cloud credentials, keywords...).
* **Win32 tray app** (`DlpTray.exe`) connected over a secured **named pipe**: live event
  list, alerts, and clipboard monitoring (the session-0 service can't read the clipboard).
* **Cloud integration** over WinHTTP: batched telemetry with an offline disk spool, policy
  sync with **WebSocket push**, against a small FastAPI mock backend.

See [docs/architecture.md](docs/architecture.md) for the design,
[docs/minifilter-wfp-design.md](docs/minifilter-wfp-design.md) for how blocking would be
added in kernel mode, and [docs/ai-review-log.md](docs/ai-review-log.md) for defects
found while reviewing AI-generated code.

## Build

Visual Studio 2026 (MSVC, Desktop C++ workload) and CMake 3.25+. Dependencies
(nlohmann/json, GoogleTest) are fetched by CMake.

```powershell
cmake --preset msvc
cmake --build --preset debug
ctest --preset debug                 # unit tests, no admin needed
cmake --preset msvc-analyze; cmake --build --preset analyze   # MSVC /analyze
```

## Run

ETW kernel providers require an **elevated** prompt.

```powershell
# Foreground, with debug logging (Ctrl+C to stop)
build\src\agent\Debug\DlpAgent.exe --console --verbose

# Write a test file into the monitored folder from the default policy
mkdir C:\DlpTest
Set-Content C:\DlpTest\invoice.txt "card 4111 1111 1111 1111"
#   -> VIOLATION ... "rule_id":"pci-card" ... "samples":["************1111"]

# Tray app (normal, non-elevated prompt)
build\src\tray\Debug\DlpTray.exe --show
```

End-to-end ETW check (elevated): `powershell -ExecutionPolicy Bypass -File scripts\smoke_etw.ps1`

### As a service

```powershell
build\src\agent\Debug\DlpAgent.exe --install    # auto-start, restarts on crash
sc start DlpMonitor
sc stop DlpMonitor
build\src\agent\Debug\DlpAgent.exe --uninstall
```

Data lives in `%ProgramData%\DlpMonitor` (log, synced policy, spool). Optional
`agent.json` there: `{"cloud_url": "http://127.0.0.1:8080", "device_id": "LAPTOP-01"}`.

### With the mock cloud

```powershell
python -m venv server\.venv
server\.venv\Scripts\pip install -r server\requirements.txt
server\.venv\Scripts\python server\mock_cloud.py --port 8080      # http://127.0.0.1:8080 shows events

DlpAgent.exe --console --cloud http://127.0.0.1:8080              # elevated

# Push a new policy; connected agents fetch it within a second
curl.exe -X PUT http://127.0.0.1:8080/api/v1/policy -H "Content-Type: application/json" -d "@policy/default_policy.json"
```

Cloud integration tests: start the mock on port 8099, then
`$env:DLP_CLOUD_TEST_URL="http://127.0.0.1:8099"; ctest --preset debug -R Cloud`.

## Policy

```json
{
  "version": 1,
  "monitored_paths": ["C:\\DlpTest\\"],
  "keywords": { "confidential": ["CONFIDENTIAL", "機密"] },
  "rules": [
    { "id": "pci-card", "channels": ["usb", "clipboard"], "detectors": ["credit_card"],
      "min_matches": 1, "severity": "high", "action": "alert" }
  ]
}
```

Channels: `usb` (removable volumes, including USB disks reported as fixed, plus
`monitored_paths`), `clipboard`, `network` (upload volume over `network_upload_threshold_bytes`
per process and destination per minute). Built-in detectors: `credit_card` (Luhn),
`tw_national_id` (checksum), `aws_access_key`, `github_token`, `email`; keyword sets are
named under `keywords`.

## Layout

```
src/common   event model, pipe framing + overlapped connection, bounded queue, logging
src/agent    service, ETW session/parser, trackers, detectors, policy, pipe server, cloud client
src/tray     Win32 tray app
server       FastAPI mock backend
tests        GoogleTest unit + integration tests
scripts      elevated ETW smoke test
docs         architecture, kernel enforcement design, AI review log
```

## Limitations

Detection only (ETW is asynchronous, so it can't block); text formats only (Office/PDF
containers are not extracted). See the limitations section of the architecture doc.
