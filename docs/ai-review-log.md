# AI-assisted development review log

This project was written with Claude Code. This log records defects found while reviewing
the generated code: what was wrong, how it was caught, and the fix. The point is the review
habit, not the tool.

| # | Area | Defect | Caught by | Fix |
|---|---|---|---|---|
| 1 | Pipe name | A shell heredoc collapsed `L"\\\\.\\pipe\\..."` to `L"\\.\pipe\..."`: `\p` and `\D` became unknown escapes, which would have produced a wrong pipe path. | `/W4 /WX` (C4129) | Raw string literal `LR"(\\.\pipe\DlpMonitor)"`; files written with an editor rather than heredocs. |
| 2 | Shutdown | Housekeeping loop was `while (!cv.wait_for(lock, st, 5s, []{ return false; }))`. With a stop token, `wait_for` returns the predicate, which is always `false`, so the loop never exits and `Agent::stop()` hangs on join. | Reading the code against the `condition_variable_any` stop-token overload's contract | Wait, then check `st.stop_requested()` explicitly. |
| 3 | Framing | `FrameDecoder::feed` compacted its buffer only when it was *fully* consumed. A peer that always leaves a partial frame makes the buffer grow without bound. | Review of the hostile-peer case | Erase the consumed prefix on every feed. |
| 4 | WebSocket shutdown | `close_websocket()` called during the HTTP upgrade found no handle to close; the upgrade then completed and `WinHttpWebSocketReceive` blocked forever, hanging service stop. | Thinking through stop() at every point in the connect sequence | A `shutdown_` flag under the same mutex; the upgrade path checks it before publishing the handle. |
| 5 | WebSocket shutdown | Used `WinHttpWebSocketClose`, which is synchronous and waits for the server's close frame, so a dead backend stalls shutdown. | API documentation check | Close the handle, which cancels the pending receive. |
| 6 | Static analysis | Unannotated `wWinMain`; a possibly-null mutex handle passed to `CloseHandle`. | MSVC `/analyze` (C28251, C6387) | SAL annotations; `UniqueHandle`. The WinHTTP upgrade's `nullptr, 0` buffer is documented usage and is suppressed with a comment. |
| 7 | Tests | A pipe test contained `sleep_for(100ms)` "to let the server register the client". This hid the real guarantee (history is sent under the same lock that registers the client) and would have made the test flaky on a loaded CI box. | Asking why the sleep was needed | Removed; the ordering guarantee is now stated in a comment. |
| 8 | Repo hygiene | The Visual Studio `.gitignore` template does not ignore `build/`; the first commit included the CMake build tree and FetchContent sources. | `git show --stat` before pushing | Ignore `/build*/` and amend the unpublished commit. |
| 9 | Portability | `std::getenv` triggers C4996 under `/WX`. | Compiler | `GetEnvironmentVariableA`. |

## Pitfalls designed out before the code was written

These were raised during design review rather than found as bugs, but they are the kind of
thing generated code commonly gets wrong, so the code and tests guard them explicitly.

* **ETW feedback loop**: the scanner's own `CreateFile` on a monitored file produces
  Kernel-File events that would schedule another scan forever. File events whose header
  PID is the agent's are dropped.
* **Close vs Cleanup**: Kernel-File Close (14) waits for the last reference, and the cache
  manager holds one on cached files, sometimes for minutes. Cleanup (13), the last user
  handle closing, is the scan trigger.
* **Overlapped I/O lifetime**: returning with a read or write in flight lets the kernel
  later write into a destroyed stack buffer and `OVERLAPPED`. Every exit path in
  `PipeConnection` does `CancelIoEx` and then `GetOverlappedResult(..., TRUE)`.
* **Header PID for process events**: Kernel-Process start events carry the *creator's*
  PID in the header; the new process's PID is the `ProcessID` property.

## Review checklist used

* **Lifetimes across threads and the kernel**: who owns each buffer while I/O is in flight?
  What happens if stop() is called at each line of the connect/start path?
* **Hostile input**: pipe frames, cloud policy and clipboard content are all untrusted. Is
  every size bounded? Is a bad policy rejected *before* anything changes?
* **Callbacks from C**: no exception may unwind through ETW or SCM frames.
* **Back-pressure**: what blocks when a consumer is slow, and is that what we want?
* **Compiler as reviewer**: `/W4 /WX /permissive-` always, `/analyze` preset before commits.
* **Tests assert guarantees, not timing**: no sleeps that stand in for synchronization.

## Not yet verified on a live system

The ETW keyword masks and property names (`FileObject`, `FileName`, `IOSize`, `PID`,
`daddr`, ...) follow the provider manifests but were written without an elevated session
available. `scripts/smoke_etw.ps1` checks them end to end; check its output before relying
on the ETW path. (`wevtutil gp Microsoft-Windows-Kernel-File /ge /gm` lists the manifest.)
