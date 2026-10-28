# DLP Monitor：防毒 / EDR 排除設定指引

適用對象：部署 DLP Monitor 的企業 IT 與資安團隊。
適用版本：`<版本號>`　　文件更新日期：`<YYYY-MM-DD>`

> 本文件是範本。發布前請替換所有 `<...>` 欄位，並在各 EDR 的實際環境中驗證步驟。

---

## 1. 為什麼需要設定排除

DLP Monitor 是端點資料外洩防護（DLP）agent。為了偵測敏感資料外流，它會進行下列行為，部分 EDR 可能將其判定為可疑：

- 以 LocalSystem 身分執行的自動啟動 Windows service
- 建立 ETW（Event Tracing for Windows）session，監看全系統的檔案、程序與網路事件
- 讀取寫入 USB 裝置與受監控資料夾的檔案內容
- 每個使用者 session 的 tray 程式讀取剪貼簿文字
- 透過 HTTPS / WebSocket 連線至管理伺服器，上傳事件並接收政策更新

DLP Monitor **不會**：注入其他程序、hook 系統 API、停止其他產品的 ETW session、隱藏自身程序，或上傳原始檔案內容（只上傳遮罩後的比對樣本，例如 `************1111`）。

未設定排除時可能發生：

1. agent 被隔離或阻擋，DLP 防護失效
2. EDR 與 agent 重複掃描同一檔案，造成額外的 CPU 與磁碟負載
3. ETW session 建立或剪貼簿存取被行為防護阻擋

---

## 2. 建議的排除方式：以簽章憑證信任

| 方式 | 建議 | 說明 |
|---|---|---|
| **簽章憑證（publisher）** | ✅ 優先 | 只信任由本公司私鑰簽章的檔案；產品更新後不需修改 |
| 程序排除（process） | 有效能問題時加入 | 讓 EDR 不重複掃描 agent 開啟的檔案 |
| 檔案 hash | 僅在 EDR 不支援憑證時 | 每個版本都需要更新 |
| 路徑 | 不建議單獨使用 | 該目錄下的任何檔案都會被信任 |

---

## 3. 產品識別資訊

### 3.1 簽章憑證

| 欄位 | 值 |
|---|---|
| Subject | `CN=<公司法定名稱>, O=<公司法定名稱>, L=<城市>, C=TW` |
| Issuer | `<CA 名稱>` |
| Thumbprint (SHA-1) | `<THUMBPRINT>` |
| 有效期限 | `<YYYY-MM-DD>` 至 `<YYYY-MM-DD>` |
| 憑證檔 | `DlpMonitor-signer.cer`（隨本文件提供） |

### 3.2 檔案

| 檔案 | 安裝路徑 | SHA-256（版本 `<版本號>`） |
|---|---|---|
| `DlpAgent.exe` | `C:\Program Files\DlpMonitor\DlpAgent.exe` | `<SHA256>` |
| `DlpTray.exe` | `C:\Program Files\DlpMonitor\DlpTray.exe` | `<SHA256>` |

### 3.3 系統資源

| 項目 | 值 |
|---|---|
| Windows service | `DlpMonitor`（顯示名稱：DLP Monitor Agent，LocalSystem，自動啟動） |
| 資料目錄 | `C:\ProgramData\DlpMonitor\`（log、設定、離線佇列） |
| Named pipe | `\\.\pipe\DlpMonitor`（agent 與 tray 之間的本機通訊） |
| ETW session | `DlpMonitor-Agent` |
| ETW providers | Microsoft-Windows-Kernel-Process、Microsoft-Windows-Kernel-File、Microsoft-Windows-Kernel-Network |
| 網路連線 | `<管理伺服器網域>`，TCP 443（HTTPS / WSS） |

---

## 4. 各產品設定步驟

### 4.1 Microsoft Defender for Endpoint

**信任憑證（建議）**
1. 開啟 Microsoft Defender portal → **Settings** → **Endpoints** → **Indicators** → **Certificates**
2. **Add item** → 上傳 `DlpMonitor-signer.cer`
3. Action 選 **Allow**，Scope 選擇要部署 DLP Monitor 的裝置群組

**程序排除（有效能問題時）**
- Intune：Endpoint security → Antivirus → Microsoft Defender Antivirus exclusions → **Processes** 加入
  `C:\Program Files\DlpMonitor\DlpAgent.exe`
- 或 GPO：Computer Configuration → Administrative Templates → Windows Components → Microsoft Defender Antivirus → Exclusions → **Process Exclusions**

### 4.2 Trend Micro Apex One

`<待驗證：信任憑證 / 核准程式清單的設定路徑>`

### 4.3 CrowdStrike Falcon

`<待驗證：Machine learning exclusion 與 IOA exclusion 的設定方式>`

### 4.4 其他產品

在產品中尋找下列設定（名稱因產品而異）：

1. **Trusted certificate / Trusted publisher / Signer allowlist**：匯入 `DlpMonitor-signer.cer`
2. **Process exclusion / Trusted process**：加入 `DlpAgent.exe` 完整路徑
3. 若行為防護阻擋 ETW 或剪貼簿存取：針對上述程序建立行為規則例外

如需協助，請聯絡 `<技術支援信箱>`。

---

## 5. 驗證

在端點上以 PowerShell 確認安裝的檔案是由本公司簽章且未被竄改：

```powershell
Get-AuthenticodeSignature "C:\Program Files\DlpMonitor\DlpAgent.exe" |
    Format-List Status, @{n='Thumbprint'; e={$_.SignerCertificate.Thumbprint}}
# Status 應為 Valid，Thumbprint 應與 3.1 節一致

Get-FileHash "C:\Program Files\DlpMonitor\DlpAgent.exe" -Algorithm SHA256
# 應與 3.2 節一致

Get-Service DlpMonitor
# Status 應為 Running
```

---

## 6. 憑證續約

簽章憑證續約後 thumbprint 會改變。本公司會在舊憑證到期**至少 60 天前**提供新的 `.cer` 與 thumbprint。
過渡期間請**同時信任新舊兩張憑證**，待所有端點都更新至新憑證簽章的版本後，再移除舊憑證。

| 憑證 | Thumbprint | 有效期限 | 狀態 |
|---|---|---|---|
| 目前 | `<THUMBPRINT>` | `<YYYY-MM-DD>` | 使用中 |
| 下一張 | — | — | — |
