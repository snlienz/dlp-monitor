# Production release 檢查清單

本文整理把 DLP Monitor 從 demo 推到正式部署時會遇到的問題：權限、授權與憑證、防毒誤判，以及其他上線前必須補齊的項目。
每一節都對照目前程式碼的實際狀態（✅ 已具備 / ⚠️ 部分 / ❌ 尚未處理）。

> 憑證價格、SmartScreen 與驅動程式簽章政策會變動，發布前請以 Microsoft 與 CA 官方文件為準。

---

## 1. 權限（Admin）

### 1.1 為什麼一定需要高權限

| 動作 | 需要的權限 | 程式位置 |
|---|---|---|
| 建立 ETW real-time session 並啟用 Kernel-File / Process / Network provider | Administrator 或 SYSTEM | [etw_session.cpp](../src/agent/etw_session.cpp) `StartTraceW` |
| 安裝 / 移除 Windows service | Administrator（SCM `SC_MANAGER_CREATE_SERVICE`） | [service.cpp](../src/agent/service.cpp) |
| 讀取任何使用者寫到 USB / 監控路徑的檔案 | SYSTEM（多數 ACL 都有 SYSTEM） | [content_scanner.cpp](../src/agent/content_scanner.cpp) |
| 寫入 `C:\ProgramData\DlpMonitor` 並設定 protected DACL | Administrator / SYSTEM | [config.cpp](../src/agent/config.cpp) `ensure_data_dir` |

結論：**agent 必須以 service（LocalSystem）執行**，這是 DLP / EDR 類產品的常態，無法降到一般使用者權限。
Tray（`DlpTray.exe`）不需要 admin，它只連 named pipe 和讀剪貼簿。

### 1.2 企業部署時使用者不會看到 UAC

正式環境不是讓使用者「右鍵 → 以系統管理員執行」，而是：

- 打包成 **MSI**（WiX Toolset），由 Intune / SCCM (ConfigMgr) / GPO 以 SYSTEM 身分靜默安裝。
- MSI 的 `ServiceInstall` / `ServiceControl` 取代 `DlpAgent.exe --install`，升級時自動 stop → 替換 → start。
- Tray 透過 `HKLM\...\Run` 為每個登入的使用者啟動（RDS / 快速切換使用者時每個 session 一個 tray）。

### 1.3 要補強的地方

| 狀態 | 項目 |
|---|---|
| ✅ | 啟動時偵測未提權並給出明確錯誤（`main.cpp` `is_elevated`） |
| ✅ | Service 路徑加引號，避免 unquoted service path 劫持 |
| ✅ | Data dir protected DACL；named pipe DACL 只允許 SY/BA 完整權限、IU 讀寫 |
| ❌ | **最小權限**：用 `SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO` 只保留需要的 privilege，並設定 service SID |
| ❌ | **讀不到排除 SYSTEM 的檔案**：`read_file_prefix` 沒有用 `FILE_FLAG_BACKUP_SEMANTICS` + `SeBackupPrivilege`，ACL 刻意排除 SYSTEM 的檔案會掃描失敗 |
| ❌ | **防竄改**：本機 admin 可以 `sc stop DlpMonitor`。至少要收緊 service 的 DACL（禁止非 SYSTEM 停止）、雲端偵測 heartbeat 中斷並告警。PPL（Protected Process Light）需要 ELAM driver 與 Microsoft 防毒計畫資格，一般 DLP 廠商拿不到，不要列為目標 |
| ❌ | ETW session 數量上限（系統全域 64 個）：與客戶端 EDR 共存時可能 `StartTrace` 失敗，需要重試與告警 |

---

## 2. 需要 Microsoft License 嗎？

### 2.1 不需要付費授權的部分

- **Windows API 本身**（ETW、SCM、WinHTTP、Named Pipe、Clipboard）：不用額外授權或權利金，任何人都可以用 Windows SDK 開發並發布商業軟體。
- **user-mode service 不需要 Microsoft 簽章或審核**。只要用一般 CA 發的 code signing 憑證自己簽即可（見 §3）。

### 2.2 需要注意的授權

| 項目 | 說明 | 動作 |
|---|---|---|
| **Visual Studio** | Community 版：個人開發者可做商業產品；非企業組織最多 5 人；「企業」（超過 250 台 PC 或年營收超過 100 萬美元）除開源、教學、研究外不可使用。Build Tools 與 VS Code + MSVC 也要求持有有效的 VS 授權 | 公司開發用 VS Professional / Enterprise 訂閱 |
| **VC++ Runtime** | Release 版的 `vcruntime140.dll` 等可依 VS 授權條款再散佈；**Debug runtime（`*d.dll`）不可散佈** | 只發 Release build；用 VC++ Redistributable 或 `/MT` 靜態連結 |
| **第三方元件** | nlohmann/json（MIT） | 安裝包附 `THIRD_PARTY_NOTICES` |
| **本專案** | Apache-2.0 | 若改為閉源商業產品需確認著作權歸屬 |

### 2.3 如果之後加入 kernel driver（minifilter / WFP）

這時才真正牽涉到 Microsoft 的流程（設計見 [minifilter-wfp-design.md](minifilter-wfp-design.md)）：

1. **EV code signing 憑證**（向 CA 購買，綁硬體 token / HSM）。
2. **Microsoft Partner Center 硬體開發者帳號**（需要用 EV 憑證註冊）。
3. **Attestation signing**：上傳 driver 給 Microsoft 簽章，Windows 10/11 client 才能載入。Windows Server 需要走 **WHQL / HLK** 測試。
4. **Minifilter altitude**：向 Microsoft 申請（免費），不可自行挑選數字。
5. 開發階段只能用 test-signing 模式（`bcdedit /set testsigning on`），HVCI / Secure Boot 環境要另外驗證相容性。

---

## 3. 如何避免被防毒 / EDR 誤判

### 3.1 為什麼 DLP agent 很容易被誤判

從行為分析引擎的角度，這個程式的行為跟資料竊取型惡意程式幾乎一樣：

| DLP 的合法行為 | 惡意程式的類似行為 |
|---|---|
| 安裝 auto-start service，以 SYSTEM 執行 | 持久化 + 提權 |
| 開 kernel ETW session 監看全系統檔案 / 程序 / 網路 | 偵察 |
| 讀取使用者剛寫入的檔案內容、讀剪貼簿 | 資料蒐集、竊取 |
| 透過 WinHTTP + WebSocket 連到伺服器、接收指令（policy push） | C2 通訊 |
| 停止名稱相同的既有 ETW session（`ERROR_ALREADY_EXISTS` 處理） | ETW tampering（關掉 EDR 的 telemetry） |
| 未簽章、新編譯、全世界只有少數機器有這個檔案 | 低信譽樣本 |

所以重點是：**讓檔案可被識別、可被信任、行為透明**。

### 3.2 必做（發布前）

1. **所有 binary 都要 code signing**：`DlpAgent.exe`、`DlpTray.exe`、DLL、MSI 本身都簽，並加 **RFC 3161 timestamp**（憑證過期後簽章仍有效）。
   ```
   signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 /a DlpAgent.exe
   ```
   - 選項：一般 OV 憑證（2023 年起私鑰必須放在硬體 token / HSM）、EV 憑證，或 Microsoft 的雲端簽章服務（Azure Trusted Signing，有申請資格限制）。
   - **固定使用同一個 publisher 憑證**：SmartScreen 與防毒的信譽是跟著憑證累積的，換憑證等於重新開始。EV 憑證現在也不再保證立即通過 SmartScreen，仍需要累積信譽。
2. **加入 VERSIONINFO resource**（目前 ❌ 沒有）：`CompanyName`、`ProductName`、`FileDescription`、`FileVersion`。沒有版本資訊的 SYSTEM service 本身就是可疑特徵。
3. **只發 Release build**，不要用 UPX 之類的 packer、不要混淆字串。壓縮 / 加殼幾乎一定被標記。
4. **安裝到 `C:\Program Files\DlpMonitor\`**，不要從 `%TEMP%`、`%APPDATA%`、Downloads 執行 service。
5. **只停止自己的 ETW session**：目前程式只停同名的 `DlpMonitor-Agent` session，這點要保持，並在文件中寫明。絕不碰其他廠商的 session。

### 3.3 發布流程（每個版本）

每次重新編譯 hash 都會改變，對防毒引擎而言是信譽為零的新檔案。若不事先送審，客戶大量部署時 agent 可能在所有端點同時被隔離。

```
Release build → 簽章 + timestamp → 本機驗證
   → 送 Microsoft + 客戶使用的防毒廠商（記錄 submission ID）
   → 更新 EDR 排除指引（hash、版本；憑證沒換就不用動）
   → pilot ring 1–5% → 觀察 heartbeat / 安裝失敗 → 全面部署
```

**1. 本機驗證**
```powershell
Get-AuthenticodeSignature .\DlpAgent.exe | Format-List Status, SignerCertificate, TimeStamperCertificate
& "$env:ProgramFiles\Windows Defender\MpCmdRun.exe" -Scan -ScanType 3 -File "C:\release\DlpAgent.exe"
```

**2. 送 Microsoft**：`https://www.microsoft.com/en-us/wdsi/filesubmission`，身分選 **Software developer**，上傳簽章後的 exe 與 MSI。說明欄寫明產品用途（企業 DLP agent）、為何使用 ETW 與讀取檔案、公司網站與聯絡方式。結果同時影響 Defender 與 SmartScreen。

**3. 送其他廠商**：先確認目標客戶使用的產品（台灣企業常見 Trend Micro Apex One，另有 Symantec/Broadcom、Kaspersky、ESET、Sophos）。各家提交管道網址常變動，搜尋「`<廠商> false positive submission`」或「`<廠商> software vendor allowlist`」。有軟體廠商白名單計畫的廠商盡量**以憑證登記**，之後版本不必逐一送審。CrowdStrike、SentinelOne 等 EDR 通常沒有公開管道，由客戶依 [EDR 排除指引](edr-exclusion-guide.md) 設定。

**4. 記錄送審結果**

| 版本 | 廠商 | 送審日期 | Submission ID | 結果 |
|---|---|---|---|---|
| | Microsoft | | | |
| | Trend Micro | | | |

**5. 分階段部署**：先推給 1–5% 的端點，heartbeat 中斷或安裝失敗通常代表被隔離；確認後再全面推送。

**注意**：未公開版本**不要上傳 VirusTotal**，上傳等於把 binary 公開給所有防毒廠商與付費會員下載。

### 3.4 客戶端 EDR 排除指引

客戶的 EDR 仍可能隔離 agent、與 agent 重複掃描同一檔案，或阻擋 ETW / 剪貼簿行為。提供 [edr-exclusion-guide.md](edr-exclusion-guide.md) 給客戶 IT。

| 排除方式 | 優點 | 缺點 |
|---|---|---|
| 路徑 | 簡單 | 放在該目錄的任何檔案都被信任 |
| Hash | 最精確 | 每個版本都要更新 |
| **憑證（建議）** | 換版不用改；只有你的私鑰簽的檔案被信任 | 憑證續約時 thumbprint 改變，需提前 30–60 天通知客戶並讓新舊憑證並存 |

每個版本產生指引所需的資料：
```powershell
$sig = Get-AuthenticodeSignature .\DlpAgent.exe
$sig.SignerCertificate | Export-Certificate -FilePath .\DlpMonitor-signer.cer
$sig.SignerCertificate | Format-List Subject, Issuer, Thumbprint, NotAfter
Get-FileHash .\DlpAgent.exe, .\DlpTray.exe -Algorithm SHA256
```

### 3.5 行為上降低可疑度

- Tray 圖示與說明清楚告知「本機受 DLP 監控」（透明性也是法規要求，見 §4）。
- 雲端連線**只允許 HTTPS / WSS**（目前 `http://` 也能用，⚠️ 正式版應拒絕），伺服器憑證驗證不可關閉。
- 上傳內容維持「只送遮罩後的樣本」（✅ 已做到），不要上傳原始檔案。
- 不做 process injection、不 hook、不隱藏自己。

---

## 4. 其他 production 問題

### 4.1 法規與隱私
- 監控員工檔案與剪貼簿涉及**個人資料保護法**（台灣）、GDPR（歐盟員工）：需要事前告知、明確的蒐集目的、保存期限。
- Log 與事件包含檔名、程序名稱、使用者活動，本身就是敏感資料：本機 log 需要輪替與保存期限（目前 ❌ 沒有 log rotation），雲端需要存取控制與稽核。

### 4.2 雲端與安全
| 狀態 | 項目 |
|---|---|
| ✅ | 離線 spool，連不上時不遺失事件 |
| ❌ | **裝置身分驗證**：目前 telemetry / policy API 沒有任何 auth header，任何人都能冒充裝置上傳或拉取 policy。需要 per-device token 或 mTLS（client certificate） |
| ❌ | **Policy 完整性**：從雲端推送的 policy 應簽章驗證，避免被中間人或惡意伺服器關掉偵測 |
| ❌ | 自動更新機制（下載的更新檔要驗證簽章），以及失敗回滾 |

### 4.3 穩定性與效能
- Service 失敗自動重啟（✅ 前兩次 5 秒後重啟）。
- 需要 crash dump（WER LocalDumps 或 `MiniDumpWriteDump`）才能分析客戶端當機。
- 已知效能風險：同一檔案每次關閉 handle 都從頭重掃（log 類檔案會反覆讀 8 MB）、超過 `scan_limit_bytes`（8 MB）的內容不掃描、每個 worker 掃描時約佔 3–4 倍檔案大小的記憶體、queue 滿（1024）時丟棄掃描。上線前需要在一般辦公電腦上量測 CPU / 記憶體並設定上限。
- ETW 事件遺失（`etw_lost`、`buffers_lost`）要回報到雲端儀表板，不能只寫在本機 log。

### 4.4 相容性測試矩陣
- Windows 10 22H2、Windows 11 (23H2/24H2)、Windows Server 2019/2022。
- x64 與 ARM64（Surface / Copilot+ PC）。
- 與常見 EDR / 防毒共存、RDS 多使用者、Fast User Switching、BitLocker To Go 的 USB。

---

## 5. 上線前最小清單

- [ ] Release build，VERSIONINFO resource，所有檔案簽章 + timestamp
- [ ] MSI 安裝包（service 安裝 / 升級 / 移除、tray 自動啟動）
- [ ] 雲端：強制 HTTPS、裝置驗證、policy 簽章
- [ ] Service DACL 收緊、最小 privilege
- [ ] Log rotation、crash dump
- [ ] 送 Microsoft 與目標客戶的防毒廠商做 false positive 白名單
- [ ] 提供客戶 EDR 排除指引（以憑證為準）與隱私告知範本
- [ ] 相容性測試矩陣跑過一輪
