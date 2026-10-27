# Adding enforcement: minifilter and WFP design

The user-mode agent can only *observe*. This note describes how a production DLP product
adds kernel components to *block*, and how they would plug into this codebase. Nothing here
is implemented: building and loading drivers needs the WDK and test-signing mode (or an
EV-signed, Microsoft-attested driver).

## Why ETW cannot block

ETW events are written into per-CPU buffers and delivered to consumers later (up to the
`FlushTimer`, 1 s here). When `Agent::on_file` sees a Write, the data is already in the cache
manager; by Cleanup the user has finished copying. The best user mode can do after the fact
is alert, quarantine (move/delete the copy) or eject the volume. All three are racy.

## File system minifilter

A minifilter registers with the Filter Manager (`FltRegisterFilter`) at an altitude in the
"Activity Monitor / Content Screener" range and receives pre- and post-operation callbacks
for each I/O on each volume it attaches to.

```
 app WriteFile ─► I/O manager ─► FltMgr ─► [DlpFilter pre-write] ─► NTFS/FAT/exFAT ─► disk
                                               │      ▲
                                 FltSendMessage│      │verdict (allow / deny)
                                               ▼      │
                                         DlpAgent (user mode, FltGetMessage)
```

Design sketch:

| Piece | Callback / API | Behaviour |
|---|---|---|
| Volume attach | `InstanceSetupCallback` | Attach only to removable/USB volumes (`FltGetVolumeProperties`, `IoGetDeviceProperty` bus type), plus policy-configured paths. Skipping fixed disks keeps overhead off normal I/O. |
| Track writers | `IRP_MJ_CREATE` post-op | If the open has write access, allocate a **stream-handle context** (`FltAllocateContext`) recording PID and "dirty = false". Replaces `FileTracker`'s FILE_OBJECT map, with lifetime managed by FltMgr instead of guessed from events. |
| Mark dirty | `IRP_MJ_WRITE` pre-op | Set dirty. For strict mode, hold the write: pend it (`FLT_PREOP_PENDING`) and ask user mode. |
| Scan point | `IRP_MJ_CLEANUP` pre-op | If dirty, `FltSendMessage` `{volume, file id, pid}` to the agent and wait (timeout ~3 s). The agent opens the file by ID, scans with the existing `PolicyEngine`, and replies. On deny the filter can't un-write, so it marks the file for deletion (`FltSetInformationFile` + `FileDispositionInformation`) and the agent raises an alert. |
| Strict mode | `IRP_MJ_WRITE` pre-op | Buffer writes to a shadow file on a fixed disk and only copy to the USB volume after a verdict. This is how commercial "block copy to USB" works without a race, at the cost of complexity and latency. |
| Communication | `FltCreateCommunicationPort` | Port DACL restricted to SYSTEM; the agent connects with `FilterConnectCommunicationPort`. Max one connection; if the agent dies, the filter fails open or closed per policy. |

Pitfalls to talk through:

* **Deadlocks**: the agent's own reads of the file re-enter the filter. Exclude the agent's
  PID (as `Agent::on_file` already does for ETW) or tag the agent's opens with an ECP.
* **Re-entrancy / stack depth**: never issue I/O from a pre-op on the same instance without
  `FltCreateFileEx2` targeting the instance *below* you.
* **Timeouts**: a hung agent must not hang Explorer. Every `FltSendMessage` has a timeout
  and a fail-open/fail-closed policy decision.
* **IRQL**: pre-write can arrive at APC_LEVEL for paging I/O; only do work at PASSIVE_LEVEL
  and skip paging I/O (`FlagOn(Data->Iopb->IrpFlags, IRP_PAGING_IO)`).
* **Tamper resistance**: protect the service and driver (ELAM/PPL for the service, a
  driver-side check that the connecting process is the signed agent).

## Windows Filtering Platform (network)

Uploads to personal cloud storage, webmail or AI tools are the network exfil channel.
`NetworkTracker` currently flags volume after the fact via Kernel-Network ETW.

| Option | Layer | Use |
|---|---|---|
| User-mode WFP filters (`FwpmFilterAdd0`) | `FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6` | Block a process or destination outright (e.g. block `curl.exe` to non-corporate IPs). No driver needed; good first step. |
| Callout driver (`FwpsCalloutRegister`) | `ALE_AUTH_CONNECT` + `STREAM_V4/V6` | Inspect stream data per flow. TLS means the payload is encrypted, so content inspection there is limited to metadata (SNI, sizes). |
| Browser extension + native messaging | — | Where content inspection of uploads to SaaS/AI sites actually happens: the extension sees the file or pasted text *before* encryption and asks the agent for a verdict over native messaging. |

A realistic product combines: WFP for coarse destination control, a browser extension for
content-aware web uploads, and the minifilter for removable media and network shares.

## Mapping onto this codebase

* `PolicyEngine` and the detectors are unchanged; a minifilter verdict request is just
  another `Job` (`ScanFile` with a reply handle).
* `FileTracker` disappears; file lifetime comes from FltMgr contexts.
* A new `FilterPortClient` thread replaces the Kernel-File part of `Agent::on_file`.
* Policy gains `action: "block"`, which the filter honours and the ETW path reports as
  "would block" (useful for rolling out new rules in audit mode first).
