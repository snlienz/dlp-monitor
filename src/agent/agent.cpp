#include "agent/agent.h"

#include <ws2tcpip.h>

#include <chrono>
#include <format>
#include <fstream>
#include <sstream>

#include "agent/content_scanner.h"
#include "common/log.h"
#include "common/wstr.h"

namespace dlp {
namespace {

// Kernel-Process
constexpr USHORT kProcessStart = 1;
constexpr USHORT kProcessStop = 2;
constexpr ULONGLONG kProcessKeyword = 0x10;  // WINEVENT_KEYWORD_PROCESS

// Kernel-File
constexpr USHORT kFileCreate = 12;
constexpr USHORT kFileCleanup = 13;
constexpr USHORT kFileWrite = 16;
constexpr ULONGLONG kFileKeywords = 0x20 /*FILEIO*/ | 0x80 /*CREATE*/ | 0x200 /*WRITE*/;

// Kernel-Network
constexpr USHORT kTcpSendV4 = 10;
constexpr USHORT kTcpSendV6 = 26;
constexpr ULONGLONG kNetworkKeywords = 0x10 /*IPV4*/ | 0x20 /*IPV6*/;

constexpr int64_t kNetworkWindowMs = 60'000;

std::string read_all(const std::wstring& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return {};
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

std::string format_remote_v4(uint64_t addr, uint64_t port_be) {
    const auto port = static_cast<uint16_t>(((port_be & 0xff) << 8) | ((port_be >> 8) & 0xff));
    return std::format("{}.{}.{}.{}:{}", addr & 0xff, (addr >> 8) & 0xff, (addr >> 16) & 0xff,
                       (addr >> 24) & 0xff, port);
}

std::string format_remote_v6(std::span<const unsigned char> addr, uint64_t port_be) {
    if (addr.size() != 16) return "?";
    in6_addr a{};
    std::memcpy(&a, addr.data(), 16);
    char buf[INET6_ADDRSTRLEN]{};
    ::inet_ntop(AF_INET6, &a, buf, sizeof(buf));
    const auto port = static_cast<uint16_t>(((port_be & 0xff) << 8) | ((port_be >> 8) & 0xff));
    return std::format("[{}]:{}", buf, port);
}

bool is_loopback(const std::string& remote) {
    return remote.starts_with("127.") || remote.starts_with("[::1]");
}

std::shared_ptr<const Policy> load_initial_policy(const Config& c) {
    for (const auto& path :
         {c.policy_path, c.synced_policy_path(), exe_dir() + L"\\default_policy.json"}) {
        if (path.empty()) continue;
        const auto text = read_all(path);
        if (text.empty()) continue;
        try {
            auto p = Policy::parse(text);
            log::info("loaded policy v{} from {} ({} rules)", p->version, to_utf8(path), p->rules.size());
            return p;
        } catch (const std::exception& e) {
            log::error("policy {} rejected: {}", to_utf8(path), e.what());
        }
    }
    throw std::runtime_error("no valid policy found");
}

}  // namespace

Agent::Agent(Config config)
    : config_(std::move(config)),
      engine_(load_initial_policy(config_)),
      network_(engine_.current()->network_upload_threshold_bytes, kNetworkWindowMs),
      etw_(L"DlpMonitor-Agent", [this](const EVENT_RECORD& r) { on_etw(r); }) {}

Agent::~Agent() { stop(); }

void Agent::start() {
    volumes_.refresh();

    const unsigned n = std::max(2u, std::thread::hardware_concurrency() / 4);
    for (unsigned i = 0; i < n; ++i) {
        workers_.emplace_back([this, i] {
            ::SetThreadDescription(::GetCurrentThread(), std::format(L"scan-{}", i).c_str());
            scan_worker();
        });
    }
    housekeeping_ = std::jthread([this](std::stop_token st) { housekeeping(st); });

    etw_.start({
        {kKernelProcessProvider, kProcessKeyword, TRACE_LEVEL_INFORMATION, {kProcessStart, kProcessStop}},
        {kKernelFileProvider, kFileKeywords, TRACE_LEVEL_INFORMATION, {kFileCreate, kFileCleanup, kFileWrite}},
        {kKernelNetworkProvider, kNetworkKeywords, TRACE_LEVEL_INFORMATION, {kTcpSendV4, kTcpSendV6}},
    });

    DlpEvent ev;
    ev.kind = EventKind::Status;
    ev.time_ms = now_ms();
    ev.message = std::format("agent started, policy v{}", policy_version());
    publish(ev);
}

void Agent::stop() {
    // Order matters: stop producers first so workers can drain what's already queued.
    etw_.stop();
    jobs_.close();
    for (auto& w : workers_)
        if (w.joinable()) w.join();
    workers_.clear();
    if (housekeeping_.joinable()) {
        housekeeping_.request_stop();
        hk_cv_.notify_all();
        housekeeping_.join();
    }
}

void Agent::publish(const DlpEvent& event) {
    for (const auto& s : sinks_) s->publish(event);
}

bool Agent::submit_text(std::string channel, std::string text, uint32_t pid) {
    return jobs_.try_push(ScanText{std::move(channel), std::move(text), pid});
}

void Agent::apply_policy(std::string_view json_text, bool persist) {
    auto p = Policy::parse(json_text);  // throws before anything changes
    const int version = p->version;
    engine_.update(std::move(p));
    if (persist) {
        // Write-then-rename so a crash never leaves a truncated policy behind.
        const auto tmp = config_.synced_policy_path() + L".tmp";
        {
            std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
            f.write(json_text.data(), static_cast<std::streamsize>(json_text.size()));
        }
        ::MoveFileExW(tmp.c_str(), config_.synced_policy_path().c_str(),
                      MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);
    }
    log::info("policy v{} applied", version);

    DlpEvent ev;
    ev.kind = EventKind::Status;
    ev.time_ms = now_ms();
    ev.message = std::format("policy v{} applied", version);
    publish(ev);
}

// ---- ETW thread --------------------------------------------------------------------------

void Agent::on_etw(const EVENT_RECORD& r) {
    etw_events_.fetch_add(1, std::memory_order_relaxed);
    const GUID& provider = r.EventHeader.ProviderId;
    if (::IsEqualGUID(provider, kKernelFileProvider)) {
        on_file(r);
    } else if (::IsEqualGUID(provider, kKernelProcessProvider)) {
        on_process(r);
    } else if (::IsEqualGUID(provider, kKernelNetworkProvider)) {
        on_network(r);
    }
}

void Agent::on_process(const EVENT_RECORD& r) {
    const USHORT id = r.EventHeader.EventDescriptor.Id;
    if (id != kProcessStart && id != kProcessStop) return;
    if (!parser_.parse(r)) return;
    // The header PID is the *creating* process; the subject is in the payload.
    const auto pid = static_cast<uint32_t>(parser_.u64(L"ProcessID").value_or(0));
    if (id == kProcessStart) {
        const auto nt = parser_.str(L"ImageName");
        auto resolved = volumes_.resolve(nt);
        std::wstring image = resolved ? std::move(resolved->dos_path) : std::wstring(nt);
        if (config_.verbose) log::debug("process start {} {}", pid, to_utf8(image));
        processes_.on_start(pid, std::move(image));
    } else {
        if (config_.verbose) log::debug("process stop {}", pid);
        processes_.on_stop(pid);
    }
}

bool Agent::monitored(const ResolvedPath& p, const Policy& policy) const {
    if (p.removable) return true;
    if (policy.monitored_paths.empty()) return false;
    const auto lower = to_lower(p.dos_path);
    for (const auto& prefix : policy.monitored_paths)
        if (lower.starts_with(prefix)) return true;
    return false;
}

void Agent::on_file(const EVENT_RECORD& r) {
    const USHORT id = r.EventHeader.EventDescriptor.Id;
    if (id != kFileCreate && id != kFileWrite && id != kFileCleanup) return;
    // Our own scanner opens every file it inspects; without this we'd scan in a loop.
    if (r.EventHeader.ProcessId == self_pid_) return;
    if (!parser_.parse(r)) return;
    const auto fo = parser_.u64(L"FileObject");
    if (!fo) return;

    if (id == kFileCreate) {
        auto resolved = volumes_.resolve(parser_.str(L"FileName"));
        if (!resolved) return;
        const auto policy = engine_.current();
        if (!monitored(*resolved, *policy)) return;
        files_.on_create(*fo, std::move(resolved->dos_path), r.EventHeader.ProcessId);
    } else if (id == kFileWrite) {
        files_.on_write(*fo, parser_.u64(L"IOSize").value_or(0));
    } else if (auto written = files_.on_cleanup(*fo)) {
        if (!jobs_.try_push(ScanFile{std::move(written->path), written->pid, written->bytes}))
            log::warn("scan queue full, dropped file job");
    }
}

void Agent::on_network(const EVENT_RECORD& r) {
    const USHORT id = r.EventHeader.EventDescriptor.Id;
    if (id != kTcpSendV4 && id != kTcpSendV6) return;
    if (!parser_.parse(r)) return;
    const auto pid = static_cast<uint32_t>(parser_.u64(L"PID").value_or(0));
    if (pid == self_pid_ || pid == 0) return;
    const auto size = parser_.u64(L"size").value_or(0);
    const auto port = parser_.u64(L"dport").value_or(0);
    const std::string remote = id == kTcpSendV4
                                   ? format_remote_v4(parser_.u64(L"daddr").value_or(0), port)
                                   : format_remote_v6(parser_.bin(L"daddr"), port);
    if (is_loopback(remote)) return;

    network_.set_threshold(engine_.current()->network_upload_threshold_bytes);
    if (const auto total = network_.on_send(pid, remote, size, now_ms())) {
        DlpEvent ev;
        ev.kind = EventKind::NetworkUpload;
        ev.time_ms = now_ms();
        ev.pid = pid;
        ev.image = to_utf8(processes_.image(pid));
        ev.target = remote;
        ev.bytes = *total;
        ev.channel = "network";
        ev.severity = "medium";
        ev.message = std::format("{} MB sent within {} s", *total >> 20, kNetworkWindowMs / 1000);
        publish(ev);
    }
}

// ---- scanner workers ---------------------------------------------------------------------

void Agent::scan_worker() {
    while (auto job = jobs_.pop()) {
        try {
            std::visit([this](const auto& j) { handle(j); }, *job);
        } catch (const std::exception& e) {
            log::error("scan job failed: {}", e.what());
        }
    }
}

void Agent::handle(const ScanFile& job) {
    files_scanned_.fetch_add(1, std::memory_order_relaxed);
    const auto policy = engine_.current();
    const auto image = to_utf8(processes_.image(job.pid));
    const auto path = to_utf8(job.path);

    DlpEvent write;
    write.kind = EventKind::FileWrite;
    write.time_ms = now_ms();
    write.pid = job.pid;
    write.image = image;
    write.target = path;
    write.bytes = job.bytes;
    write.channel = "usb";

    const auto raw = read_file_prefix(job.path, policy->scan_limit_bytes);
    const auto text = raw ? decode_text(*raw) : std::nullopt;
    write.message = !raw ? "could not open file" : !text ? "binary content not scanned" : "scanned";
    publish(write);
    if (!text) return;

    for (auto& v : engine_.evaluate("usb", *text)) {
        v.pid = job.pid;
        v.image = image;
        v.target = path;
        v.bytes = job.bytes;
        violations_.fetch_add(1, std::memory_order_relaxed);
        publish(v);
    }
}

void Agent::handle(const ScanText& job) {
    const auto image = to_utf8(processes_.image(job.pid));
    for (auto& v : engine_.evaluate(job.channel, job.text)) {
        v.pid = job.pid;
        v.image = image;
        v.target = job.channel;
        v.bytes = job.text.size();
        violations_.fetch_add(1, std::memory_order_relaxed);
        publish(v);
    }
}

// ---- housekeeping ------------------------------------------------------------------------

void Agent::housekeeping(std::stop_token st) {
    ::SetThreadDescription(::GetCurrentThread(), L"housekeeping");
    using namespace std::chrono_literals;
    auto next_heartbeat = std::chrono::steady_clock::now() + 60s;
    std::unique_lock lock(hk_mu_);
    while (true) {
        hk_cv_.wait_for(lock, st, 5s, [] { return false; });
        if (st.stop_requested()) break;
        // Drive letters change on USB insert/remove; 5 s polling keeps this simple. A service
        // could instead register for GUID_DEVINTERFACE_VOLUME arrival notifications.
        volumes_.refresh();

        if (std::chrono::steady_clock::now() >= next_heartbeat) {
            next_heartbeat += 60s;
            const auto s = etw_.stats();
            DlpEvent ev;
            ev.kind = EventKind::Status;
            ev.time_ms = now_ms();
            ev.message = std::format(
                "heartbeat: etw_events={} etw_lost={} buffers_lost={} files_scanned={} "
                "violations={} queue_dropped={} policy=v{}",
                etw_events_.load(), s.events_lost, s.buffers_lost, files_scanned_.load(),
                violations_.load(), jobs_.dropped(), policy_version());
            log::info("{}", ev.message);
            publish(ev);
        }
    }
}

}  // namespace dlp
