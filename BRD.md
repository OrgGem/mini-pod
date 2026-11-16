# BRD & Đặc tả Kỹ thuật Chung — mini-pod (v2.1)

- **Phiên bản:** `v2.1`
- **Ngày cập nhật:** `2026-11-17`
- **Trạng thái:** Đã chốt kiến trúc & mô hình tin cậy/sở hữu tài nguyên (MVP `v0.1.0-rc2`)

## Quyết định Kiến trúc Chốt (Executive Decision)

Quyết định kiến trúc được chốt theo đúng đề xuất: **duyệt hướng QEMU-First cho lộ trình Spike và MVP 9 tuần**, đồng thời hạ cấp các giả định tối ưu hóa (snapshot dưới 500 ms trên TCG, tương thích mọi workload Docker, chạy xuyên mọi chính sách khóa máy trạm) từ cam kết sản phẩm xuống mục tiêu đo kiểm hoặc cột mốc sau MVP.

Bản đặc tả kỹ thuật **v2.1** dưới đây cập nhật lại toàn bộ hợp đồng API Rust, ranh giới module, cơ chế bảo mật cục bộ và cổng nghiệm thu để làm tài liệu chuẩn trước khi viết code Tuần 1.

## 1. Cam kết Vận hành và Hợp đồng Cô lập

Cam kết chính thức của sản phẩm được chuẩn hóa lại như sau:

> Cài đặt và vận hành không yêu cầu nâng quyền (unprivileged) trên các môi trường được hỗ trợ; tăng tốc phần cứng được sử dụng khi máy chủ đã cung cấp sẵn quyền và tính năng cần thiết.

Trên Windows doanh nghiệp bật AppLocker, WDAC hoặc EDR chặn thực thi tệp nhị phân trong thư mục người dùng, runtime sẽ trả lỗi chẩn đoán tường minh thay vì cam kết chạy portable tuyệt đối nếu tổ chức chưa cấp phép đường dẫn hoặc chữ ký số.

| Chế độ Runtime | Ranh giới Cô lập | Điều kiện Host | Quy tắc Fallback |
| --- | --- | --- | --- |
| QEMU + KVM, HVF, WHPX | Guest kernel riêng | Có quyền dùng thiết bị tăng tốc | Lùi về TCG nếu `Preferred` |
| QEMU + TCG | Guest kernel riêng | Cho phép chạy binary QEMU | Dừng và báo lỗi nếu bị chặn |
| Rootless Podman | Dùng chung host kernel | Bật userns, subuid, subgid | Cấm tự fallback từ VM |

Quy tắc bất biến về bảo mật: khi người gọi yêu cầu `VmRequired`, hệ thống chỉ được phép chuyển từ ảo hóa phần cứng sang giả lập phần mềm `TCG`, tuyệt đối không tự động lùi sang Rootless Podman (`userns`) vì làm thay đổi ranh giới cô lập nhân hệ điều hành. Rootless Podman chỉ chạy khi cấu hình chỉ định rõ `SharedKernelAllowed` và máy chủ Linux đã thỏa mãn điều kiện phụ thuộc.

## 2. Kiến trúc Phân lớp và Tổ chức Cargo Workspace

Điểm thay đổi cốt lõi về cấu trúc là bổ sung **Runtime Manager** làm tầng sở hữu vòng đời, kiểm soát cấp phát (admission control), thuê bao (lease), nhật ký phục hồi (journal) và kế toán tài nguyên, tách khỏi tầng backend chỉ làm nhiệm vụ bật tắt tiến trình QEMU.

```text
[CLI / Rust SDK / MCP Server / Docker Clients]
                      |
                      v
     [API Adapters + Local Authentication]
     (Unix Socket / Named Pipe DACL / Opt-in mTLS)
                      |
                      v
     [Runtime Manager (sandbox-runtime)]
     (Lifecycle, Leases, Warm Pool, Admission, Journal)
        |                 |                    |
        v                 v                    v
[QEMU Backend]   [Image & Cache Mgr]   [Host Policy Engine]
(KVM/HVF/WHPX    (Signed Bundles,      (Egress Proxy, Copy I/O,
  -> TCG)         CoW Overlays)         Port Map, Quotas)
        |                                      |
        +------------------+-------------------+
                           |
             [Versioned Multiplexed Transport]
             (virtio-serial baseline / probed vsock)
                           |
        +------------------+-------------------+
        | Linux Guest (PID 1: tiny-init)       |
        |                  |                   |
        |                  v                   |
        |         [Guest Agent Daemon]         |
        |           /              \           |
        |          v                v          |
        | [Execution Supervisor]  [Podman Unix Socket]
        +--------------------------------------+
```

Danh sách các crate trong workspace được phân tách lại trách nhiệm:

* `sandbox-core`: Kiểu dữ liệu miền, hợp đồng chính sách, thang đo năng lực thực thi, máy trạng thái và mã lỗi định danh.
* `sandbox-protocol`: Định dạng khung nhị phân (framing), thương lượng phiên bản, phân luồng ưu tiên và kiểm soát luồng (backpressure) dùng chung cho Host và Guest.
* `sandbox-vmm`: Một trình điều khiển QEMU dùng chung cho cả ba hệ điều hành, tách riêng các module nhỏ theo OS để xử lý tiến trình, IPC và dò tìm phần cứng.
* `sandbox-image`: Kiểm tra chữ ký manifest, quản lý gói tài nguyên, tạo đĩa nhánh Copy-on-Write nguyên tử và quản lý bộ đệm snapshot (sau MVP).
* `sandbox-runtime`: Runtime Manager điều phối vòng đời, thuê bao TTL, nhật ký thu hồi crash, bể máy chờ (Warm Pool), truyền tệp an toàn và Host Egress Proxy.
* `sandbox-docker-compat`: Bộ chuyển đổi tương thích Docker API, cấp phát cổng Host, viết lại siêu dữ liệu mạng và xử lý nâng cấp kết nối HTTP.
* `sandbox-client`: SDK Rust gọn nhẹ dành riêng cho ứng dụng nhúng, không chứa mã nguồn máy chủ hay MCP.
* `bins/sandboxd` và `bins/sandbox-cli`: Daemon quản lý cục bộ, công cụ dòng lệnh và bộ chuyển đổi giao thức MCP.
* `guest/tiny-init` và `guest/sandbox-agent`: Tách riêng tiến trình PID 1 (gắn kết hệ tệp gốc chỉ đọc, thu dọn tiến trình zombie, chuyển tiếp tín hiệu tắt máy) khỏi daemon RPC và bộ chuyển tiếp Unix socket của Podman.

## 3. Hợp đồng API Rust Lõi Đã Hiệu chỉnh

Các định nghĩa dưới đây thay thế hoàn toàn giao diện cũ ở bản nháp đầu tiên, khắc phục triệt để lỗi tự hủy `Box<Self>`, thiếu đích thực thi và thiếu ngân sách vật lý:

```rust
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IsolationMode {
    VmRequired,
    SharedKernelAllowed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccelerationPolicy {
    Required,
    Preferred,
    SoftwareOnly,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NetworkPolicy {
    Isolated,
    InternetOnly,
    DomainAllowList { rules: Vec<EgressRule> },
    Unrestricted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnforcementLevel {
    HardLimit,
    BestEffort,
    Unsupported,
}

#[derive(Clone, Debug)]
pub struct ResourceBudget {
    pub guest_vcpus: u8,
    pub host_cpu_quota_Millicores: Option<u32>,
    pub guest_ram_mb: u32,
    pub host_rss_budget_mb: Option<u32>,
    pub virtual_disk_mb: u32,
    pub host_storage_budget_mb: u32,
}

#[derive(Clone, Debug)]
pub enum ExecTarget {
    Guest,
    Container { id_or_name: String },
}

#[derive(Clone, Debug)]
pub struct ExecRequest {
    pub target: ExecTarget,
    pub argv: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub cwd: Option<String>,
    pub user: Option<String>,
    pub deadline: Duration,
    pub stdout_budget_bytes: u64,
    pub stderr_budget_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DestroyStatus {
    ProcessExited { remaining_artifacts: Vec<PathBuf> },
    AllResourcesCleaned,
}

#[async_trait::async_trait]
pub trait RuntimeManager: Send + Sync {
    async fn spawn(&self, spec: SandboxSpec) -> Result<SandboxLease, SandboxError>;
    async fn renew_lease(&self, id: &SandboxId, ttl: Duration) -> Result<(), SandboxError>;
    async fn exec_stream(&self, id: &SandboxId, req: ExecRequest) -> Result<ExecStream, SandboxError>;
    async fn copy_in(&self, id: &SandboxId, src_host: PathBuf, dst_guest: String) -> Result<(), SandboxError>;
    async fn copy_out(&self, id: &SandboxId, src_guest: String, dst_host: PathBuf) -> Result<(), SandboxError>;
    /// Thao tác lũy đẳng (idempotent), an toàn khi gọi lặp lại từ trình đối soát phục hồi
    async fn destroy(&self, id: &SandboxId) -> Result<DestroyStatus, SandboxError>;
}
```

Khi lệnh `exec_stream` chạm ngưỡng `deadline` hoặc vượt `stdout_budget_bytes`, Execution Supervisor bên trong máy ảo hủy toàn bộ cây tiến trình (process group hoặc cgroup con) thay vì chỉ đóng luồng đọc phía Host. Mọi chính sách giới hạn tài nguyên, hệ tệp và mạng đều áp dụng đồng nhất cho cả `ExecTarget::Guest` lẫn `ExecTarget::Container`.

## 4. Giải quyết 6 Rủi ro Kỹ thuật Trọng tâm

### 4.1. Lộ trình Khởi động, Warm Pool và Snapshot Cache

Luồng gọi `savevm` trên **base.qcow2** rồi `loadvm` trên **worker.qcow2** bị loại bỏ vì snapshot nội bộ của QEMU gắn chặt với trạng thái các ổ đĩa ghi tại thời điểm chụp và không tự kế thừa sang tệp overlay mới. Việc chỉ lưu RAM ra tệp cũng không đủ để khôi phục vì thiếu thanh ghi vCPU, bộ định thời, trạng thái thiết bị ảo và mốc dữ liệu khối tương ứng.

| Chiến lược | Mốc Áp dụng | Cơ chế Vận hành | Ràng buộc Kỹ thuật |
| --- | --- | --- | --- |
| Cold Boot | MVP Tuần 3 | Khởi động mới từ ảnh gốc chỉ đọc và đĩa nhánh qcow2 | Độ trễ phụ thuộc tốc độ TCG hoặc bộ tăng tốc |
| Warm Pool | MVP Tuần 8 | Giữ sẵn số lượng nhỏ VM sạch đã sẵn sàng nhận lệnh | Tốn RAM chờ; cạn bể phải qua hàng đợi cấp phát |
| State Snapshot | Sau MVP | Khôi phục trạng thái CPU, thiết bị, RAM và đĩa đồng bộ | Phụ thuộc chặt vào khóa cấu hình phần cứng |

Mốc dưới 500 ms chỉ được ghi nhận làm mục tiêu đo cho đường cấp phát từ **Warm Pool** còn sẵn máy, không cam kết làm SLA cho mọi lệnh `spawn()`. Khi triển khai Snapshot ở giai đoạn sau MVP, bản chụp được quản lý như bộ nhớ đệm phụ thuộc khóa cấu hình gồm: bản dựng QEMU, kiểu máy, bộ tăng tốc, mẫu CPU, kiến trúc Guest, dung lượng RAM/vCPU, sơ đồ thiết bị, mã băm ảnh đĩa và phiên bản giao thức Agent. Ngay sau khi khôi phục, Guest Agent phải tạo lại định danh phiên, nạp bù entropy mới từ Host, đồng bộ đồng hồ, nối lại kênh truyền và chỉ nhận thông tin xác thực sau khi khôi phục xong; mọi VM đã chạy mã không tin cậy đều bị hủy bỏ một chiều.

### 4.2. Ma trận macOS, Kiến trúc CPU và Giao thức Truyền tải

* **Tách bạch API trên macOS:** MVP dùng thống nhất QEMU trên cả ba hệ điều hành để giảm phân mảnh; trên macOS, QEMU dùng `-accel hvf` (Hypervisor.framework) và lùi về `-accel tcg` khi thiếu tăng tốc phần cứng. Backend gốc dựa trên Virtualization.framework (đòi hỏi pipeline đĩa RAW riêng cùng các quyền entitlement đặc thù cho ảo hóa và mạng như vmnet) cùng bản dựng Windows ARM64 được chuyển sang lộ trình sau MVP.
* **Kênh truyền chuẩn và Xác thực Cục bộ:** Dùng `virtio-serial` làm kênh truyền mặc định trên mọi nền tảng (kiểm chứng `-chardev pipe` trên Windows và `-chardev socket` trên Unix trong Tuần 1), còn `virtio-vsock` chỉ bật khi dò tìm thấy hỗ trợ. Phía Host khóa quyền truy cập bằng Unix socket (quyền tệp 0600 trong thư mục 0700 của người dùng) trên Linux/macOS và Named Pipe gắn DACL giới hạn đúng SID chủ sở hữu trên Windows; chỉ mở TCP khi cấu hình yêu cầu kèm mTLS. Phía Guest, Podman chỉ lắng nghe trên Unix socket nội bộ và được Guest Agent chuyển tiếp, xóa bỏ hoàn toàn cổng TCP 2375.
* **Phân luồng Ưu tiên:** Giao thức trong `sandbox-protocol` đóng gói phiên bản, mã luồng `stream_id`, giới hạn kích thước khung và cửa sổ tín dụng (credit-based backpressure), tách riêng làn điều khiển ưu tiên cao để luồng log hoặc sao chép tệp lớn không làm nghẽn lệnh hủy hoặc tắt máy.

### 4.3. Gán Job Object Lúc Khởi tạo và Nhật ký Phục hồi Crash

* **Khóa Khoảng hở Tạo Tiến trình Windows:** Tiến trình QEMU và mọi tiến trình phụ trợ được gắn vào Job Object (bật cờ `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`) ngay trong lời gọi `CreateProcessW` thông qua thuộc tính `PROC_THREAD_ATTRIBUTE_JOB_LIST`, kết hợp danh sách trắng `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` để ngăn rò rỉ hoặc nhân bản handle sang tiến trình con khác.
* **Journal và Đối soát Khởi động:** Trước mỗi bước cấp phát hoặc thu hồi, Runtime Manager ghi trạng thái vào tệp nhật ký bền vững cục bộ kèm thời hạn thuê bao (lease/heartbeat). Khi daemon khởi động lại sau sự cố sập nguồn hoặc bị buộc dừng giữa chừng, trình đối soát (startup reconciler) quét nhật ký để diệt tiến trình mồ côi, thử lại thao tác xóa tệp theo giới hạn lùi mũ và cập nhật tách biệt hai mốc `ProcessExited` với `AllResourcesCleaned`.

### 4.4. Chính sách Mạng Egress Chống Vượt rào

Bốn chế độ mạng được chuẩn hóa không chồng chéo: `Isolated` (mặc định; gỡ bỏ hoàn toàn thiết bị NIC ảo khi toàn bộ điều khiển đi qua virtio, hoặc rà soát sạch mọi ngoại lệ chuyển tiếp của cờ `restrict=on`), `InternetOnly`, `DomainAllowList` và `Unrestricted` (chỉ bật khi khai báo tường minh).

* Trong chế độ `InternetOnly` và `DomainAllowList`, Host Egress Proxy nối qua kênh virtio là đường ra duy nhất (triệt tiêu đường vòng qua truy vấn DNS trực tiếp hoặc giao thức UDP/QUIC).
* Bộ lọc trên Host kiểm tra đầy đủ cả IPv4 lẫn IPv6 (loopback, dải riêng tư RFC1918, link-local, ULA, IPv4 ánh xạ sang IPv6 và các dải đặc biệt), chuẩn hóa tên miền, kiểm tra cổng đích, đồng thời **phân giải DNS trên Host, kiểm duyệt IP rồi mở kết nối TCP trực tiếp tới chính IP đó** (kiểm tra lại ở mọi bước HTTP redirect) để chặn tấn công DNS Rebinding.
* Cấu hình proxy được tiêm đồng bộ vào cả dịch vụ Podman (phục vụ kéo ảnh container) lẫn biến môi trường của tiến trình trong container. Tài liệu công bố rõ: HTTP CONNECT/SOCKS chỉ kiểm soát đích kết nối chứ không giải mã luồng TLS và không ngăn được rò rỉ dữ liệu nếu tên miền nằm trong danh sách cho phép hỗ trợ nhận tải lên.

### 4.5. Bộ Chuyển đổi Tương thích Docker API (`sandbox-docker-compat`)

Thành phần này được định vị chính xác là **Docker API Compatibility Adapter** cho tập tính năng và phiên bản client đã qua kiểm thử (thư viện `bollard` chỉ dùng ở phía client và bộ test tích hợp; lệnh `podman play kube` chỉ giới hạn ở việc chạy Pod từ tập cấu hình YAML mà Podman hỗ trợ):

* **Cổng Dịch vụ (Published Ports):** Khi container xuất cổng nội bộ (ví dụ cổng 5432), Adapter tự mở listener trên Host, nối đường truyền xuyên qua kênh virtio vào máy ảo và viết lại trường địa chỉ/cổng trong phản hồi inspect để các công cụ như Testcontainers kết nối trực tiếp từ Host.
* **Ánh xạ Thư mục và Luồng Streaming:** Từ chối tường minh các yêu cầu bind mount đường dẫn thô từ máy chủ (`C:\...` hoặc `/Users/...`) chưa qua cơ chế đồng bộ thư mục được cấp phép; kiểm thử đầy đủ cơ chế nâng cấp HTTP hijack, đóng nửa kết nối (half-close) của lệnh `exec`/`attach`, luồng log/sự kiện, truyền kho lưu trữ tar và quy trình dọn dẹp container Ryuk của Testcontainers.

### 4.6. Hợp đồng Sao chép Workspace và Kế toán Tài nguyên Thực tế

* **Copy-in / Execute / Copy-out cho MVP:** Không đánh đồng truyền luồng tar với live mount; MVP thực hiện sao chép thư mục làm việc vào máy ảo trước khi chạy và chỉ trích xuất các tệp kết quả được chỉ định ra ngoài. Bộ giải nén phía Host chặn tuyệt đối chuỗi vượt cấp (`..`), đường dẫn tuyệt đối, symlink, hardlink và Windows reparse point/junction. Live mount được hoãn sang sau MVP kèm đặc tả riêng về khóa tệp và theo dõi thay đổi tệp.
* **Báo cáo Năng lực Thực thi (`EnforcementLevel`):** Tách rõ số lượng vCPU với hạn ngạch CPU thực, dung lượng RAM máy ảo với tổng RSS của QEMU cùng bộ đệm, và kích thước đĩa ảo với ngân sách đĩa vật lý thực tế trên Host (gộp tệp qcow2 overlay, nhật ký và bộ đệm). Không dùng memory ballooning hay trình OOM trong Guest làm hàng rào bảo vệ Host; trên Linux, nếu cgroup v2 chưa được ủy nhiệm (delegate) đúng quyền, hệ thống báo rõ trạng thái `BestEffort` hoặc `Unsupported` thay vì âm thầm giả lập thành công.

## 5. Đối chiếu Tham khảo `dualeai/exec-sandbox` và Chuỗi Cung ứng Đóng gói

Trước khi trích xuất mẫu thiết kế từ kho mã `dualeai/exec-sandbox`, nhóm phát triển ghim cố định mã commit tham chiếu và kiểm soát giả định môi trường theo bảng sau:

| Cơ chế Upstream | Giả định Môi trường | Phạm vi Tái sử dụng | Bài Test Xác nhận |
| --- | --- | --- | --- |
| Tiny-init và rootfs chỉ đọc | Guest kernel quản lý mount | Dùng tách PID 1; gắn thêm overlay ghi cho Podman | Diệt tiến trình con, kiểm tra không còn zombie |
| Kênh virtio-serial | QEMU hỗ trợ thiết bị ký tự | Giữ hướng không qua NIC; viết mới framing ưu tiên | Xả log tối đa đồng thời gửi lệnh hủy khẩn cấp |
| Bể chờ Warm Pool | Host còn dư ngân sách RAM | Giữ quy tắc hủy VM bẩn; thêm kiểm soát cấp phát | Gửi tải vượt kích thước bể, đo trần RSS của Host |
| Cgroups phía Host | Linux đã cấu hình quyền trước | Chỉ bật tùy chọn khi dò thấy quyền hợp lệ | Chạy bằng user chuẩn, kiểm tra cờ báo capability |

Về đóng gói phát hành, thay vì dùng `sevenz-rust` giải nén tùy ý các bộ cài đặt `.exe` bên ngoài ngay lúc chạy, hệ thống CI đóng gói và kiểm thử sẵn các bản **Portable Runtime Bundle** theo từng cặp OS/kiến trúc (gồm binary QEMU, firmware, ảnh đĩa gốc và Guest Agent đã ghim phiên bản). Trình nạp khởi tạo xác thực mã băm SHA-256 dựa trên **Manifest được ký số Ed25519** (khóa công khai nhúng cứng trong binary) rồi hoán đổi thư mục nguyên tử; các con số kích thước (như mục tiêu gói 85 MB và agent 2 MB) được theo dõi qua phép đo thực tế trên CI.

## 6. Lộ trình MVP 9 Tuần và Cổng Nghiệm thu Bắt buộc

Kế hoạch dưới đây ước lượng cho hai kỹ sư toàn thời gian có kinh nghiệm về Rust và ảo hóa hệ thống, tách toàn bộ tính năng phức tạp (Memory Snapshot ngoài, native Virtualization.framework, Live Mount, BuildKit parity, Windows ARM64) sang các cột mốc sau MVP:

| Thời gian | Phạm vi Công việc | Điều kiện Hoàn thành |
| --- | --- | --- |
| Tuần 1 | Spike thực nghiệm trên Windows user chuẩn, Linux, macOS | Boot QEMU, bắt tay qua virtio-serial, chạy lệnh và dọn sạch; chốt IPC và quyền |
| Tuần 2 | Pipeline dựng ảnh đĩa và đóng gói Bundle ký số | Dựng ảnh lặp lại được, ghim phiên bản/digest, nạp gói nguyên tử trên x86_64 và aarch64 |
| Tuần 3–4 | Runtime Manager, QEMU backend, Job Object, Lease, Copy I/O | Chạy luồng Isolated trên ba OS; vượt bài kiểm thử sập nguồn không rò tiến trình hay tệp |
| Tuần 5–6 | Relay Podman socket, chuyển cổng và Docker Adapter | Chạy thông suốt từ đầu đến cuối bộ kiểm thử Docker SDK và Testcontainers đã chọn |
| Tuần 7 | Host Egress Proxy, kiểm soát cấp phát, kế toán tài nguyên | Chặn đứng các đường vượt rào mạng đã định nghĩa; báo đúng mức capability thiếu |
| Tuần 8 | Tích hợp Warm Pool và bộ đo kiểm độc lập | Đo tách biệt Cold Boot, Warm Checkout, Container-Ready; kiểm thử cạn bể và bù bể |
| Tuần 9 | Đóng gói SDK, CLI, MCP và diễn tập phục hồi sự cố | Phát hành bản Release Candidate kèm ma trận hỗ trợ và tài liệu giới hạn bảo mật |

### 7 Cổng Nghiệm thu Trước Khi Công bố (Release Gates)

1. Báo cáo đo kiểm tách rời bốn chỉ số độc lập trên từng nền tảng: khởi động lạnh (cold boot), lấy máy từ bể chờ (warm checkout), khôi phục snapshot (khi mở tính năng sau MVP) và thời điểm container sẵn sàng nhận kết nối (container-ready).
2. Khi lưu lượng gọi vượt cạn số máy trong Warm Pool, bộ kiểm soát cấp phát (admission/backpressure) xếp hàng hoặc từ chối có kiểm soát, giữ tổng bộ nhớ vật lý của Host dưới trần cấu hình.
3. Buộc dừng tiến trình daemon bằng tín hiệu `SIGKILL` hoặc `TerminateProcess` ngay giữa lúc đang khởi tạo hoặc đang hủy sandbox không để lại tiến trình QEMU chạy ngầm hay tệp đĩa mồ côi sau bước đối soát khởi động lại.
4. Một tài khoản người dùng thứ hai trên cùng máy Windows, Linux hoặc macOS bị hệ điều hành từ chối ngay lập tức khi thử mở kết nối tới Named Pipe hoặc Unix socket điều khiển.
5. Bộ kiểm thử bảo mật tự động xác nhận các mẫu tấn công DNS rebinding, địa chỉ IPv6 nội bộ/ánh xạ và gói tar chứa symlink hoặc đường dẫn vượt cấp đều bị chặn hoàn toàn.
6. Bộ test tích hợp Testcontainers hoàn thành trọn vẹn chu trình kéo/tạo container, kết nối thành công vào cổng dịch vụ được ánh xạ ra Host, đọc luồng log và thu dọn sạch sẽ.
7. Tác vụ cố tình ghi tràn ổ đĩa hoặc bơm vô hạn dữ liệu ra luồng `stdout`/`stderr` bị ngắt đúng hạn mức và giải phóng toàn bộ dung lượng tạm trong ngân sách vật lý đã công bố.

## 7. Mô hình Tin cậy, Phân quyền Endpoint và Quyền Sở hữu Tài nguyên

### 7.1. Mô hình Tin cậy giữa Host và Guest

Host sở hữu việc quyết định chính sách cô lập, mạng, cấp phát tài nguyên và vòng đời sandbox. `sandbox-runtime` điều phối các quyết định này; các adapter thực hiện cơ chế tương ứng và báo cáo kết quả cùng mức `EnforcementLevel`. Cấu hình và việc lựa chọn adapter được thực hiện tại composition root trong `bins/*`.

Trong chế độ `VmRequired`, ranh giới cô lập bảo vệ Host là máy ảo có kernel riêng và vòng đời dùng một lần (hủy một chiều sau khi sử dụng). Việc chuyển từ tăng tốc phần cứng sang `TCG` không làm thay đổi ranh giới này. `SharedKernelAllowed` là lựa chọn tường minh chỉ trên Linux và không bao giờ được sử dụng làm fallback tự động cho `VmRequired`.

`tiny-init` (PID 1), Guest Agent (`sandbox-agent`) và Execution Supervisor thực hiện các tác vụ bên trong Guest (gắn hệ tệp gốc chỉ đọc `MS_RDONLY`, giám sát thực thi theo `cgroup v2` / process group, giới hạn `deadline` và `stdout`/`stderr` budget, chuyển tiếp Podman Unix socket). Tuy nhiên, **Host không mặc nhiên tin cậy dữ liệu do workload tạo ra hoặc dữ liệu trả về qua kênh Guest (kể cả từ Guest Agent sau khi VM đã chạy mã không tin cậy)**: mọi thông điệp phải được kiểm tra theo hợp đồng `sandbox-protocol` (phiên bản, kích thước khung, làn ưu tiên, cửa sổ tín dụng `StreamCredit`); dữ liệu `copy-out` phải vượt qua bộ kiểm tra đường dẫn, loại entry và ngân sách kích thước/số lượng entry trên Host trước khi tác động lên filesystem Host.

Các chính sách về **ngân sách tài nguyên Host, thời hạn thực thi (`deadline`), ngân sách `stdout`/`stderr` và kiểm soát mạng Egress** phải áp dụng đồng nhất cho cả `ExecTarget::Guest` và `ExecTarget::Container`. Giới hạn thực thi bên trong Guest chỉ hỗ trợ dọn dẹp sớm, không thay thế hàng rào bảo vệ tài nguyên Host.

* **Quyền của workload bên trong Guest:**
  * Mỗi sandbox `VmRequired` là máy ảo đơn thuê bao (single-tenant). Với `ExecTarget::Guest`, người gọi được phép chỉ định danh tính Unix qua `ExecRequest.user` (bao gồm cả `0:0` / `root`, hoặc kế thừa danh tính chạy của `sandbox-agent` khi `user: None`) để phục vụ thiết lập môi trường và cài đặt gói bên trong VM; với `ExecTarget::Container`, tiến trình chịu sự giới hạn namespace/capability của Podman và bộ lọc `HostConfig` tại `sandbox-docker-compat` (từ chối `Privileged`, `CapAdd`, `Devices`, chia sẻ host namespace và các đường dẫn `/libpod/*`).
  * Podman chỉ lắng nghe trên Unix socket nội bộ của Guest (`/run/podman/podman.sock`, thư mục `0700`). Đối với container, quyền gắn socket này mặc định bị chặn (`ReaperSocketPolicy::Deny`); trường hợp container dọn dẹp Ryuk của Testcontainers yêu cầu gắn `/var/run/docker.sock` được xử lý như ngoại lệ tường minh do adapter quản lý (`ReaperSocketPolicy::MapGuestPodmanSocket`, viết lại đích gắn vào `/run/podman/podman.sock` nội bộ Guest thay vì socket trên Host).
  * Vì tiến trình chạy với quyền `root` bên trong Guest có khả năng can thiệp `sandbox-agent`, Execution Supervisor hoặc Podman socket của chính máy ảo đó, **toàn bộ bảo đảm an toàn cho Host (trần CPU/RSS qua Job Object / delegated cgroup v2, ngân sách lưu trữ vật lý, TTL lease, `-nic none` + `HostEgressProxy`, kiểm tra khung/credit IPC và giải nén `safe_tar`) bắt buộc được Host cưỡng chế độc lập bên ngoài VM**, đồng thời mọi VM đã chạy workload đều bị hủy bỏ một chiều (không bao giờ hoàn trả về `Warm Pool`).
* **Ràng buộc phiên IPC giữa Host và Guest:**
  * Ở mỗi lượt khởi tạo VM, Host cấp phát một endpoint IPC điểm-nối-điểm riêng (`virtio-serial` mặc định hoặc `virtio-vsock` khi bật) gắn cố định 1–1 với đúng một `SandboxId` và phiên tiến trình QEMU `(pid, start_token)`; Guest không có khả năng chọn hoặc chuyển hướng sang sandbox khác. *(Cơ chế cấp mới định danh phiên trên bản tin wire sẽ bắt buộc mở rộng khi triển khai State Snapshot sau MVP theo Mục 4.1.)*
  * Không gian `StreamId` phân tách rõ luồng do Host mở và luồng do Guest mở (`GUEST_STREAM_ID_BIT`). Khi Guest gửi khung sai phiên bản ở bước bắt tay, vượt cửa sổ tín dụng cho phép, hoặc gửi thông điệp sai trạng thái luồng/phiên hiện hành, Host hủy luồng vi phạm hoặc đóng ngay toàn bộ kết nối transport của VM đó và trả lỗi cho các thao tác đang chờ.

### 7.2. Quyền Truy cập Từng Endpoint

Quyền kết nối tới một endpoint và phạm vi thao tác được phép sau khi kết nối được quy định tách biệt cho từng đường giao tiếp:

| Endpoint / Đường giao tiếp | Ràng buộc kết nối & Xác thực | Phạm vi thao tác & Giới hạn |
| --- | --- | --- |
| Điều khiển cục bộ trên Host (`sandboxd` Control IPC) | Unix socket `0600` trong thư mục `0700` (từ chối symlink); Windows Named Pipe gắn DACL giới hạn đúng SID chủ sở hữu kèm cờ từ chối client từ xa. Hợp đồng kiến trúc chỉ cho phép mở TCP khi cấu hình tường minh kèm mTLS (không bao giờ coi bind loopback tương đương giới hạn UID/SID); trong MVP, mọi URI mạng (`tcp://`, `http://`, `tls://`, UNC pipe từ xa) bị từ chối mặc định (`PolicyViolation`). | Tin cậy theo phạm vi tài khoản OS: mọi client chạy cùng UID/SID sau khi kết nối được phép quản lý toàn bộ sandbox thuộc daemon của tài khoản đó. MVP không cô lập quyền giữa các ứng dụng/agent chạy chung cùng một tài khoản OS. |
| Host ↔ Guest qua virtio | `virtio-serial` mặc định (`virtio-vsock` khi dò thấy hỗ trợ), kết nối điểm-nối-điểm riêng cho từng VM; giao thức có framing giới hạn kích thước, phiên bản, phân luồng `StreamId`, làn ưu tiên control và `StreamCredit` backpressure. | Ràng buộc cứng 1–1 với một `SandboxId` và phiên tiến trình QEMU tương ứng; từ chối/đóng transport khi sai phiên bản, sai không gian `StreamId`, vượt credit hoặc sai trạng thái. |
| Guest Agent ↔ Podman | Podman lắng nghe trên Unix socket nội bộ Guest (`/run/podman/podman.sock` trong thư mục `0700`); xóa bỏ hoàn toàn TCP `2375`. | Chỉ phục vụ `sandbox-agent` (và tiến trình có quyền `root` trong Guest) cùng ngoại lệ container Ryuk khi bật tường minh `ReaperSocketPolicy::MapGuestPodmanSocket`. |
| Docker API Adapter phía Host (`sandbox-docker-compat`) | Lắng nghe trên Unix socket `0600` (thư mục `0700`) hoặc Windows Named Pipe gắn DACL owner-only; không phơi cổng TCP không xác thực ra daemon. | Gắn với một `SandboxId` xác định; chuẩn hóa đường dẫn URL/khóa JSON, chặn `/libpod/*`, từ chối bind mount thô từ Host và các cờ nâng quyền container nguy hiểm. |
| Giao diện MCP (`sandboxd mcp`) | JSON-RPC 2.0 qua `stdio`, kế thừa trực tiếp danh tính tài khoản OS của tiến trình khởi chạy MCP. | Hỗ trợ chế độ `Connected` (ủy quyền qua Control IPC owner-only tới `sandboxd` đang chạy) hoặc chế độ `Standalone` (tự khởi tạo runtime riêng với điều kiện giữ khóa độc quyền `state.lock` trên một `state_dir` tách biệt). |
| Cổng dịch vụ container được publish trên Host | `sandbox-docker-compat` mở listener TCP chỉ trên loopback `127.0.0.1` trong MVP, chuyển tiếp qua virtio vào Guest và viết lại địa chỉ/cổng trong phản hồi `inspect`/`list`. | Chưa cho phép bind LAN hay `0.0.0.0` trong MVP; tách biệt hoàn toàn với API điều khiển daemon/Docker. Lưu ý: loopback không phân quyền theo UID/SID giữa các tài khoản cục bộ trên cùng máy, dịch vụ nhạy cảm cần tự xác thực ở tầng ứng dụng. |
| Guest ↔ Host Egress Proxy | Với `InternetOnly` và `DomainAllowList`, VM khởi chạy không NIC ảo (`-nic none`) và bắt buộc đi qua `HostEgressProxy` trên virtio; Host phân giải DNS, lọc dải IPv4/IPv6 cấm và kết nối TCP trực tiếp tới IP đã duyệt (kiểm tra lại ở mọi bước HTTP redirect). | Gắn cố định với chính sách `NetworkPolicy` hiện hành của đúng sandbox đó; áp dụng giới hạn số luồng egress đồng thời trên mỗi VM cùng các ngưỡng timeout bắt tay, kết nối đích và luồng nhàn rỗi trên Host. |

### 7.3. Quyền Sở hữu Tài nguyên và Trách nhiệm Thu hồi

Trong mục này, “sở hữu” chỉ trách nhiệm quyết định vòng đời và bảo đảm thu hồi tài nguyên, không đồng nghĩa với UID/SID sở hữu đối tượng ở mức hệ điều hành. `sandbox-runtime` sở hữu vòng đời logic của sandbox; các adapter sở hữu cơ chế cấp phát/thu hồi tài nguyên thuộc phạm vi của mình và cung cấp đủ siêu dữ liệu để runtime ghi journal, đối soát và báo cáo trạng thái chính xác:

| Tài nguyên | Chủ sở hữu trách nhiệm | Nghĩa vụ vòng đời & thu hồi |
| --- | --- | --- |
| Sandbox, lease, admission và `Warm Pool` | `sandbox-runtime` | Quyết định cấp phát, gia hạn, hết hạn TTL, hủy bỏ một chiều VM bẩn và kế toán tổng tài nguyên cấp sandbox. |
| Tiến trình QEMU, helper và IPC của VMM | `sandbox-vmm` | Khởi chạy trong phạm vi khóa tiến trình của OS (Win32 Job Object + handle whitelist; Unix process group / cgroup), quản lý kênh IPC và buộc dừng tiến trình; không tự giữ lease hay quyết định chính sách. |
| Bundle, cache và đĩa nhánh `qcow2` overlay | `sandbox-image` thực thi; `sandbox-runtime` điều phối tài nguyên gắn với sandbox | Xác thực chữ ký Ed25519 + SHA-256, kích hoạt gói nguyên tử và tạo/xóa đĩa nhánh `overlay.qcow2` theo vòng đời sandbox. |
| Crash journal, `state.lock` và startup reconciliation | `sandbox-runtime` | Giữ khóa vùng trạng thái, ghi journal bền vững trước bước cấp phát/thu hồi và đối soát tài nguyên mồ côi khi khởi động lại. |
| Listener và kết nối chuyển tiếp cổng container | `sandbox-docker-compat` thực thi | Gắn chặt với vòng đời container/sandbox và đóng toàn bộ socket lắng nghe ngay khi container dừng hoặc sandbox bị hủy. |
| `HostEgressProxy` và tài nguyên phục vụ mạng | `sandbox-runtime` | Thực thi `NetworkPolicy`, quản lý kết nối ra ngoài, tác vụ chuyển tiếp và bộ đệm trong giới hạn cho phép. |
| Tiến trình thực thi bên trong Guest | `sandbox-agent` / Execution Supervisor; `tiny-init` làm PID 1 | Hủy toàn bộ `cgroup v2` con / process group khi quá `deadline`, tràn `stdout`/`stderr` budget hoặc nhận lệnh hủy ưu tiên; thu dọn zombie và xử lý tín hiệu tắt máy. |

Việc tiến trình QEMU đã thoát không đồng nghĩa mọi tài nguyên đã được dọn sạch. `destroy()` bắt buộc lũy đẳng (idempotent) và chỉ trả `DestroyStatus::AllResourcesCleaned` khi toàn bộ tiến trình và tệp tạm thuộc phạm vi thu hồi của sandbox đã được xóa; nếu vẫn còn tệp chưa xóa được sau chu kỳ thử lại, hệ thống lưu lại trạng thái đối soát và trả `DestroyStatus::ProcessExited { remaining_artifacts }`.

* **Độc quyền vùng trạng thái (`state_dir`) và xác minh tiến trình mồ côi:**
  * Mỗi thư mục trạng thái bền vững (`state_dir`) tại một thời điểm chỉ do duy nhất một thực thể runtime sở hữu, được bảo đảm bằng khóa tệp OS độc quyền (`state.lock`) chiếm giữ ngay từ trước bước `reconcile_startup` cho tới hết vòng đời runtime. Thực thể thứ hai trỏ vào cùng `state_dir` sẽ bị từ chối ngay lập tức và phải kết nối qua daemon hiện hành hoặc sử dụng một `state_dir` riêng.
  * Mỗi bản ghi journal gắn với `SandboxId` và lưu cặp định danh tiến trình `(pid, start_token)` (mốc thời gian khởi tạo tiến trình do nhân OS cấp, ghi bền vững trước cả bước bắt tay IPC) để phân biệt chính xác tiến trình mồ côi với tiến trình khác đã tái sử dụng lại cùng PID. Khi không thể xác minh hoặc thu hồi an toàn, trình đối soát giữ lại bản ghi và báo cáo thu hồi chưa hoàn tất thay vì diệt tiến trình hoặc xóa tệp theo phỏng đoán.
* **Phạm vi kế toán ngân sách Host và báo cáo `EnforcementLevel`:**
  * Ngân sách cấp sandbox (`ResourceBudget`: số lượng máy ảo, hạn ngạch CPU, RSS và dung lượng lưu trữ vật lý gồm `overlay.qcow2`, journal, thư mục làm việc `sandboxes/<id>`) được kiểm soát bởi `AdmissionController` (xếp hàng FIFO có giới hạn thời gian chờ hoặc từ chối có kiểm soát với `AdmissionRejected`, luôn ưu tiên yêu cầu trực tiếp hơn tác vụ bù `Warm Pool`).
  * Các tài nguyên phục vụ nằm ngoài tiến trình QEMU bên trong không gian nhớ của Host daemon (hàng đợi khung truyền tải, bộ đệm cửa sổ tín dụng theo từng luồng `StreamId`, luồng kết nối `HostEgressProxy`, cổng chuyển tiếp và tệp `qemu-stderr.log`) được khống chế bằng trần kích thước bộ đệm cố định, giới hạn số kết nối đồng thời và timeout cứng trên từng luồng.
  * Hệ thống chỉ báo `EnforcementLevel::HardLimit` khi cơ chế hệ điều hành thực sự chặn cứng việc vượt trần (Win32 Job Object hoặc Linux delegated cgroup v2 cho CPU/RSS; `-nic none` kết hợp `HostEgressProxy` cho kiểm soát mạng). Những cơ chế dựa trên đo đạc định kỳ rồi xử lý hậu kiểm khi vượt ngưỡng (như quét dung lượng thư mục lưu trữ vật lý trên Host) bắt buộc báo cáo trung thực là `BestEffort` (hoặc `Unsupported` khi nền tảng không hỗ trợ).
* **Ngữ nghĩa ghi dữ liệu `copy-out` và bảo toàn tài nguyên dùng chung:**
  * Thao tác `copy-out` giải nén vào thư mục đích `dst_host` trên Host (tự tạo thư mục nếu chưa có; kiểm tra từng thành phần đường dẫn và từ chối tuyệt đối `..`, đường dẫn tuyệt đối, tên thiết bị đặc biệt Windows, symlink, hardlink trong tar và Windows reparse point/junction) theo cơ chế **ghi tạm và hoán đổi nguyên tử từng tệp (per-file atomic staging & rename)**: mỗi tệp regular được ghi đầy đủ và kiểm tra khớp kích thước/ngân sách vào một tệp staging mới (`create_new`) nằm ngay trong cùng thư mục cha trên cùng filesystem, đồng bộ dữ liệu rồi mới `rename` nguyên tử vào đường dẫn đích (nếu xảy ra lỗi hoặc cắt cụt dữ liệu giữa chừng, tệp staging tự động bị xóa và tệp đích cũ của mục đang lỗi được giữ nguyên). Bộ giải nén từ chối ghi đè nếu đích hiện hữu là thư mục, symlink, reparse point, node đặc biệt hoặc tệp đang có nhiều hardlink (`nlink > 1` trên Unix); tính nguyên tử được cam kết ở mức từng tệp regular riêng lẻ, không phải giao dịch hoàn tác toàn bộ cây thư mục.
  * Tách biệt tài nguyên riêng của sandbox với tài nguyên dùng chung: `destroy()` chỉ thu hồi tiến trình, kết nối, journal và thư mục riêng `sandboxes/<id>` của đúng sandbox đó. Các gói Portable Runtime Bundle dùng chung (`base.qcow2`, kernel, initramfs) luôn giữ ở chế độ chỉ đọc kèm cơ chế khóa đọc dùng chung khi nâng cấp gói để việc hủy một sandbox không bao giờ làm mất dữ liệu nền của các sandbox khác đang hoạt động; MVP chưa thực hiện tự động thu gom rác (GC) đối với kho bundle/cache dùng chung.
