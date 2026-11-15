# mini-pod — Agent Engineering Rules & Architecture Guide

## 1. Vai trò, Ngôn ngữ & Nguồn Chân lý (`BRD.md` v2.1)

- **Nguồn chuẩn duy nhất:** [BRD.md](BRD.md) (`v2.1`, hướng **QEMU-First** cho lộ trình Spike & MVP 9 tuần) là hợp đồng chuẩn về kiểu dữ liệu Rust, ranh giới cô lập, bảo mật cục bộ, tổ chức workspace và các cổng nghiệm thu. Không tự ý sửa chữ ký `RuntimeManager` hay các kiểu lõi (`IsolationMode`, `AccelerationPolicy`, `NetworkPolicy`, `EnforcementLevel`, `ResourceBudget` gồm `host_cpu_quota_Millicores`, `ExecTarget`, `ExecRequest`, `DestroyStatus`) nếu chưa cập nhật `BRD.md`.
- **Ngôn ngữ giao tiếp:** Trả lời người dùng bằng tiếng Việt ngắn gọn, rõ ràng. Mã nguồn Rust, tên kiểu/hàm, test, log, commit message và comment `shortcut:` viết bằng tiếng Anh chuẩn.
- **Tóm tắt trung thực cuối lượt (Ponytail):** Kết thúc mỗi lượt thay đổi mã nguồn hoặc kỹ thuật bằng 1–2 dòng nêu rõ: phần nào đã bỏ qua / chưa kiểm tra và rủi ro thực tế (nếu có) mà người dùng cần biết.

## 2. Triết lý Phối hợp: Clean Architecture × Kent Beck × Ponytail

Dự án áp dụng **Clean Architecture ở ranh giới giữa các crate** và **Ponytail + Kent Beck Simple Design ở bên trong từng crate**:

- **Ranh giới Macro (Clean Architecture):**
  - Chiều phụ thuộc `Cargo.toml` chỉ hướng vào trong về phía miền cốt lõi (`sandbox-core`, `sandbox-protocol`).
  - Tầng trong định nghĩa port/trait (`RuntimeManager`) và kiểu miền; tầng ngoài cài đặt adapter cụ thể (QEMU, image, Docker HTTP, CLI, MCP).
  - Composition root chỉ đặt ở lớp ngoài cùng (`bins/sandboxd`, `bins/sandbox-cli`). Crate thư viện bên trong không được tự đọc biến môi trường toàn cục hay tự khởi tạo dịch vụ ngoài sau lưng composition root.
- **Tối giản Micro (Ponytail & Kent Beck 4 Rules of Simple Design):**
  - Thứ tự ưu tiên bất biến: **(1) Qua bài kiểm thử -> (2) Bộc lộ rõ ý đồ -> (3) Không lặp logic -> (4) Ít phần tử nhất**.
  - *"The best code is the code never written"*: chọn giải pháp ngắn gọn, thẳng thắn nhất thỏa mãn đầy đủ phạm vi và bảo toàn biên an toàn. Tận dụng thư viện chuẩn Rust, API hệ điều hành và dependency sẵn có trước khi thêm crate mới.
  - **Chống Over-engineering (YAGNI):** Tuyệt đối không tạo trait, generic, wrapper, builder, config option hoặc lớp trừu tượng "cho tương lai" khi chỉ có một triển khai cụ thể và `BRD.md` không yêu cầu.
- **Quản lý Nợ Kỹ thuật Chủ đích & Sửa Lỗi Tận Gốc:**
  - Mọi giải pháp rút gọn có giới hạn biết trước phải gắn comment ngay tại dòng code theo mẫu `// shortcut: <ceiling/limit>, <upgrade trigger>` để kiểm toán bằng skill `ponytail-debt`.
  - Khi sửa bug: luôn `grep` mọi caller của hàm liên quan trước khi sửa, rồi xử lý một lần ở hàm dùng chung để không bỏ sót điểm gọi khác.
  - Mọi logic không tầm thường (rẽ nhánh phức tạp, parser, I/O an toàn, bảo mật, quản lý tiến trình/bộ nhớ) phải viết kèm ít nhất một unit/integration test thực chất chứng minh nó sai khi bị phá. Trong lúc phát triển từng task chỉ kiểm tra biên dịch nhanh (`cargo check --all-targets`) và hoãn việc chạy toàn bộ unit test sang cổng chốt cuối Phase ở Mục 5.

## 3. Bản đồ Phân lớp Cargo Workspace & Quy tắc Chiều Phụ thuộc

```text
[bins/sandboxd, bins/sandbox-cli]   (Layer 4: Composition Root, CLI, MCP, Local Auth)
        |           |           |
        v           v           v
[sandbox-docker-compat]  [sandbox-vmm]  [sandbox-image]   (Layer 3: Adapters)
        \                   |               /
         +--------+---------+--------------+
                  v
          [sandbox-runtime]                 (Layer 2: Use Cases / RuntimeManager)
                  |
                  v
    [sandbox-core] + [sandbox-protocol]     (Layer 1: Domain & Framing - Innermost)

[sandbox-client] ---> [sandbox-core] (+ client IPC, cấm kéo daemon/QEMU/MCP)
[guest/tiny-init], [guest/sandbox-agent] ---> [sandbox-protocol]
```

Trách nhiệm và biên phụ thuộc bắt buộc cho từng thành phần:

| Thành phần | Tầng | Trách nhiệm sở hữu | Cấm phụ thuộc / Cấm làm |
| --- | --- | --- | --- |
| `sandbox-core` | Layer 1 | Kiểu miền, chính sách, capability (`EnforcementLevel`), state machine, `SandboxError` | Cấm phụ thuộc `tokio` runtime I/O, HTTP, QEMU hay OS process APIs |
| `sandbox-protocol` | Layer 1 | Binary framing, thương lượng phiên bản, `stream_id`, ưu tiên control lane, credit backpressure | Cấm chứa logic QEMU, Podman hay hệ tệp Host |
| `sandbox-runtime` | Layer 2 | Triển khai `RuntimeManager` (`spawn`, `renew_lease`, `exec_stream`, `copy_in`, `copy_out`, `destroy` lũy đẳng), admission control, TTL lease, journal & startup reconciler, Warm Pool, copy tar an toàn, Host Egress Proxy | Không xử lý CLI, MCP, Docker HTTP routing |
| `sandbox-vmm` | Layer 3 | Driver QEMU chung 3 OS (`KVM`/`HVF`/`WHPX` -> `TCG`), module nhỏ theo OS cho process (Windows Job Object), IPC (`virtio-serial` mặc định; `virtio-vsock` khi dò thấy), probe phần cứng | Chỉ quản lý vòng đời VMM/IPC; cấm giữ lease, warm pool hay policy |
| `sandbox-image` | Layer 3 | Xác thực Ed25519 manifest & SHA-256 bundle, atomic swap, tạo đĩa nhánh `qcow2` CoW nguyên tử | Không chứa logic chạy VM hay HTTP |
| `sandbox-docker-compat` | Layer 3 | Docker API Adapter: mở cổng Host nối qua virtio, viết lại inspect address/port cho Testcontainers, HTTP hijack & half-close (`exec`/`attach`), từ chối bind mount thô chưa cấp phép | `bollard` chỉ được dùng ở client hoặc `dev-dependencies` để test |
| `sandbox-client` | Adapter | SDK Rust gọn nhẹ cho ứng dụng nhúng | Cấm kéo vào daemon server, `sandbox-vmm` hay MCP |
| `bins/sandboxd`, `bins/sandbox-cli` | Layer 4 | Composition root: đọc cấu hình, khóa xác thực cục bộ, nối các adapter vào `sandbox-runtime`, phục vụ CLI & MCP | Không crate thư viện nào được phụ thuộc ngược vào `bins/*` |
| `guest/tiny-init`, `guest/sandbox-agent` | Guest | `tiny-init` làm PID 1 (rootfs ro + overlay rw cho Podman, thu dọn zombie, tín hiệu tắt máy); `sandbox-agent` (mục tiêu ~2 MB) chạy RPC, Execution Supervisor (diệt cả process group / cgroup con khi quá `deadline` hoặc tràn `stdout`/`stderr` budget), relay Podman Unix socket | Cấm mở cổng TCP 2375 trong Guest; cấm chỉ đóng stream phía Host mà bỏ mặc tiến trình con |

## 4. Bất biến Bảo mật & Độ tin cậy Tuyệt đối ("Never Cut")

Ponytail cấm cắt giảm ranh giới tin cậy và an toàn dữ liệu. Khi triển khai hoặc review, mọi thay đổi chạm các hạng mục sau đều phải kiểm tra đủ trường hợp biên:

1. **Ranh giới Cô lập (`IsolationMode`):** Khi `VmRequired`, chỉ được lùi từ tăng tốc phần cứng sang `TCG` (nếu `AccelerationPolicy::Preferred`); **cấm tuyệt đối** tự động lùi sang Rootless Podman (`userns`). Rootless Podman chỉ chạy trên Linux khi cấu hình tường minh `SharedKernelAllowed`. Trên Windows bị AppLocker/WDAC/EDR chặn binary, trả lỗi chẩn đoán tường minh thay vì ngầm vượt rào.
2. **Khóa Tiến trình & Phục hồi Crash:**
   - Windows: mọi tiến trình QEMU và tiến trình phụ trợ phải gắn Job Object (`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`) ngay trong `CreateProcessW` qua `PROC_THREAD_ATTRIBUTE_JOB_LIST`, kết hợp danh sách trắng `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`.
   - Runtime Manager ghi crash journal bền vững trước mỗi bước cấp phát và thu hồi. Startup reconciler khi khởi động lại phải diệt tiến trình mồ côi, thử lại xóa tệp theo exponential backoff, và báo tách biệt `ProcessExited` với `AllResourcesCleaned`. `destroy()` bắt buộc lũy đẳng (idempotent).
3. **Xác thực IPC Cục bộ:** Unix socket quyền `0600` trong thư mục `0700` trên Linux/macOS; Named Pipe gắn DACL giới hạn đúng SID chủ sở hữu trên Windows; chỉ mở TCP khi cấu hình yêu cầu tường minh kèm mTLS.
4. **Chống Vượt rào Mạng Egress & DNS Rebinding:**
   - Mặc định là `Isolated` (gỡ bỏ NIC ảo khi điều khiển đi qua virtio, hoặc rà sạch ngoại lệ chuyển tiếp của `restrict=on`).
   - `InternetOnly` và `DomainAllowList` ép mọi kết nối qua Host Egress Proxy trên virtio (không cho DNS trực tiếp hay UDP/QUIC đi vòng).
   - Bộ lọc Host chặn đủ IPv4 và IPv6 nội bộ/đặc biệt (loopback, RFC1918, link-local, ULA, IPv4-mapped IPv6), **phân giải DNS trên Host, kiểm duyệt IP rồi mở TCP trực tiếp tới chính IP đó** (kiểm tra lại ở từng bước HTTP redirect).
5. **Giải nén & Sao chép Workspace An toàn:** MVP dùng Copy-in / Execute / Copy-out. Bộ giải nén phía Host từ chối tuyệt đối `..`, đường dẫn tuyệt đối, symlink, hardlink và Windows reparse point/junction.
6. **Kế toán Tài nguyên & Báo cáo `EnforcementLevel` Trung thực:** Tách bạch vCPU với host CPU quota, guest RAM với host RSS budget, virtual disk với host storage budget (tính cả qcow2 overlay, journal, cache). Không dùng memory ballooning hoặc guest OOM làm hàng rào bảo vệ Host; báo rõ `BestEffort` hoặc `Unsupported` khi thiếu quyền OS (ví dụ Linux thiếu delegated cgroup v2).
7. **Chuỗi Cung ứng & Tham khảo Upstream:** Portable Runtime Bundle phải qua xác thực chữ ký Ed25519 (khóa công khai nhúng cứng) + SHA-256 và hoán đổi thư mục nguyên tử; không giải nén `.exe` bên ngoài tùy ý lúc chạy. Trước khi tham khảo mã từ `dualeai/exec-sandbox`, phải ghim commit SHA cố định và đối chiếu bảng giả định ở Mục 5 `BRD.md`.

## 5. Kỷ luật Phát triển Theo Phase, Cổng Kiểm thử Cuối Phase & Git Workflow

### Thứ tự 7 Phase tuần tự theo `BRD.md` Mục 6

Phát triển tuần tự lần lượt từng Phase (`Phase 1` -> `Phase 7`); chỉ mở `Phase N+1` sau khi `Phase N` đã hoàn tất mọi task và vượt qua đủ 4 bước ở cổng chốt cuối Phase:
- **Phase 1 (Tuần 1):** Spike thực nghiệm QEMU trên Windows user chuẩn, Linux, macOS (`virtio-serial` `-chardev pipe` / `-chardev socket`, handshake, exec, dọn sạch, chốt IPC & phân quyền).
- **Phase 2 (Tuần 2):** Pipeline dựng ảnh đĩa lặp lại được & Portable Runtime Bundle ký số Ed25519 trên `x86_64` và `aarch64`.
- **Phase 3 (Tuần 3–4):** `sandbox-core`, `sandbox-protocol`, `sandbox-runtime`, `sandbox-vmm`, Windows Job Object, TTL Lease, Crash Journal/Reconciler, Copy I/O an toàn.
- **Phase 4 (Tuần 5–6):** Relay Podman Unix socket, chuyển cổng Host và `sandbox-docker-compat` chạy bộ test Testcontainers/Docker SDK.
- **Phase 5 (Tuần 7):** Host Egress Proxy, admission control, kế toán tài nguyên & báo cáo `EnforcementLevel`.
- **Phase 6 (Tuần 8):** Warm Pool và benchmark tách biệt (`Cold Boot`, `Warm Checkout`, `Container-Ready`).
- **Phase 7 (Tuần 9):** Đóng gói `sandbox-client`, `sandbox-cli`, MCP và diễn tập phục hồi sự cố (Release Candidate).

### Quy trình thực thi từng Task trong Phase (Fast Dev + Commit & Push mỗi Task)

- Chia Phase hiện tại thành các Task nhỏ, phạm vi rõ ràng và biên dịch độc lập.
- **Không chạy full unit test (`cargo test --workspace`) sau từng task** để tránh làm gián đoạn và chậm nhịp phát triển; khi xong code và test của một task chỉ chạy kiểm tra biên dịch nhanh (`cargo check --all-targets`) để bảo đảm mã nguồn và các bài test biên dịch sạch.
- **Commit & Push ngay khi xong mỗi Task:** Kiểm tra `git status` và `git diff` (tuyệt đối không stage file tạm, `target/`, ảnh đĩa `.qcow2`/`.raw` hay khóa bí mật), viết commit message tiếng Anh theo chuẩn Conventional Commits (`feat(<scope>): ...`, `fix(<scope>): ...`, `docs: ...`, `chore: ...`) và `git push` lên `origin` ngay khi hoàn tất task.

### Cổng Chốt Cuối Mỗi Phase (End-of-Phase Gate — 4 bước bắt buộc theo thứ tự)

1. **Run Full Unit Tests:** Khi toàn bộ task của Phase đã xong, chạy một lượt đầy đủ bộ unit/component test toàn workspace (`cargo test --workspace`) cùng bài kiểm tra điều kiện hoàn thành của Phase đó.
2. **Fix Bugs:** Nếu có test thất bại hoặc phát hiện hồi quy, `grep` mọi caller liên quan, sửa tận gốc và chạy lại toàn bộ test cho tới khi xanh 100%.
3. **Consolidated Review (1 lượt):** Thực hiện một lượt review tổng thể toàn bộ mã nguồn của Phase bằng các skill đã cài (`ponytail-review`, `clean-architecture`, `kent-beck-style`) — đối chiếu chiều phụ thuộc crate, các bất biến *"Never Cut"*, loại bỏ code thừa/YAGNI và kiểm tra comment `shortcut:`. Áp dụng chỉnh sửa sau review và xác nhận full test vẫn xanh.
4. **Phase Sign-off Commit & Push:** Commit và `git push` các bản sửa lỗi / refactor chốt Phase lên `origin`, báo cáo kết quả chốt Phase rồi mới chuyển sang Phase tiếp theo.

### Danh sách Cấm Xây Sớm trong MVP (Post-MVP Deferrals)

Không viết code trong giai đoạn MVP cho các hạng mục đã hoãn sau MVP:
- State/Memory Snapshot ngoài (và tuyệt đối không dùng luồng lỗi `savevm` trên `base.qcow2` -> `loadvm` trên `worker.qcow2`).
- Backend gốc macOS `Virtualization.framework` / `vmnet`.
- Bản dựng Windows ARM64.
- Live Mount thời gian thực hai chiều.
- BuildKit parity hoàn chỉnh.
- Mốc `< 500 ms` chỉ là mục tiêu đo cho **Warm Pool checkout** (Tuần 8), không cam kết làm SLA cho mọi lệnh `spawn()`.

### Skills đã cài cho Dự án (`.agents/skills/`)

8 skills đã được cài cục bộ trong `.agents/skills/` (nguồn: `DietrichGebert/ponytail` @ `96608e078b2d5ea607c5c3b8b5a54d1c1fba6846` và `nathankim0/clean-architecture-skills` @ `e27a49df1e6c4a832206c27a66e1ec28c6dac0ba`):
- `ponytail` / `ponytail-help`: Chế độ tối giản khi viết code (`lite` / `full` / `ultra`).
- `ponytail-review` & `ponytail-audit`: Rà soát diff hoặc toàn repo theo thứ tự *Correct -> Safe -> Scale -> Tested -> Fast -> Lean*.
- `ponytail-debt` & `ponytail-gain`: Quét toàn bộ comment `shortcut:` thành danh mục nợ kỹ thuật và xem bảng đối chiếu benchmark.
- `clean-architecture`: Kiểm tra Dependency Rule, Composition Root và tách ranh giới port/adapter giữa các crate.
- `kent-beck-style`: Phát hiện code smell và refactor theo từng bước nhỏ giữ nguyên hành vi.

### 7 Cổng Nghiệm thu Trước Khi Công bố (Release Gates)

Mọi PR/cột mốc lớn phải đối chiếu với 7 cổng trong `BRD.md`:
1. Benchmark tách rời 4 chỉ số (`cold boot`, `warm checkout`, `snapshot restore` sau MVP, `container-ready`).
2. Vượt tải Warm Pool được admission/backpressure xếp hàng hoặc từ chối có kiểm soát, giữ tổng RSS Host dưới trần.
3. `SIGKILL` / `TerminateProcess` giữa lúc spawn hoặc destroy không để lại QEMU mồ côi hay đĩa rác sau startup reconciliation.
4. Tài khoản người dùng OS thứ hai bị từ chối truy cập Named Pipe / Unix socket điều khiển.
5. Test bảo mật tự động chặn hoàn toàn DNS rebinding, IPv6 nội bộ/ánh xạ và tar chứa symlink/`..`.
6. Integration test Testcontainers chạy trọn vẹn vòng đời container, kết nối cổng ánh xạ ra Host, đọc log và dọn sạch (kể cả Ryuk).
7. Tác vụ ghi tràn đĩa hoặc xả vô hạn `stdout`/`stderr` bị ngắt đúng hạn mức và giải phóng dung lượng tạm trong ngân sách vật lý.
