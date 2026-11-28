# Xerj BM25 offline trong mini-pod / TCG — 2026-11-29

**Kết luận: hoãn tích hợp vào sản phẩm.** Bản build kiểm thử tìm symbol và tài liệu
nhanh trên corpus nhỏ, nhưng cả 6 phép thử index lại đều chết với `SIGILL` trên
CPU TCG mặc định của mini-pod. Truy vấn gộp code và log cũng bỏ lỡ cả 4 câu hỏi
log trong top 5. Spike đã đo được chất lượng, RAM, dung lượng và độ trễ; chưa có
thay đổi API, runtime hay search adapter của sản phẩm.

Source Xerj được giữ nguyên tại
[`35ccd192508027cccc1b3e69f3b6721cb17cac64`](https://github.com/xerj-org/xerj/tree/35ccd192508027cccc1b3e69f3b6721cb17cac64),
phiên bản `1.0.0-rc.105`. Không dùng binary phát hành hay model Query-1.
[Harness và cách chạy lại](../../scripts/benchmarks/xerj/README.md),
[số liệu đầy đủ](xerj-bm25-tcg-evidence/summary-1024m.json),
[manifest corpus](xerj-bm25-tcg-evidence/corpus-manifest.json) được lưu cùng báo cáo.

**Điều kiện đo**

| Thành phần | Cấu hình thực tế |
| --- | --- |
| Host | Windows 10 Pro 19045; Ryzen 7 7840HS, 8 core / 16 thread; khoảng 59,7 GiB RAM |
| QEMU | `11.1.0 (v11.1.0-12130-ge470268ff4)`, `-accel tcg,tb-size=32`, `-nic none` |
| VM chính | 3 VM mới tuần tự; 1 vCPU, 1024 MiB RAM; host RSS budget 2048 MiB |
| Đĩa | ext4 trên qcow2; virtual disk 2048 MiB; host storage budget 3072 MiB |
| Cô lập | `VmRequired`, `SoftwareOnly`, `Isolated`; guest xác nhận chỉ có interface `lo` |
| Quyền hạn | IPC Named Pipe owner-only; bundle ký số được doctor xác minh; không công bố cổng host |
| Enforcement runtime báo | RSS `HardLimit`; CPU quota và host storage `BestEffort` |
| Build | Rust 1.100.0, Linux musl static PIE, `--locked --no-default-features`, `target-cpu=x86-64`, thin LTO / 16 codegen units |
| Corpus | mini-pod `e359a799946933c10b2c406d9b30c7a810ab15c2`; 92 file, 3.484.440 byte (3,32 MiB) |
| Nội dung | Rust/Markdown được chọn từ repo và 4 record JSONL chẩn đoán **giả lập** |
| Index | `--no-semantic --no-graph --workers 1 --plan no-vectors`; 3.719 record dữ liệu và 95 record catalog |
| Truy vấn | 32 câu khóa trước khi chạy: 28 positive, 4 negative; SHA-256 `a099f4013774a516617aa6d1b402e20ead47b1b8e4983159258ee3f9aabf2f1e` |

Ba lượt đều xác minh SHA-256 binary trong guest, mapping không có vector/semantic
field và dọn sạch với `AllResourcesCleaned`, không còn qcow2 của sandbox.
Build/fetch dùng mạng bên ngoài VM; toàn bộ index/search bên trong VM chạy offline.
Binary SHA-256: `6850361a0b5f82e6b7098b649089d19ea85013dc9b0e43cf8f9dc02495f89239`.

**Chất lượng tìm kiếm**

Ba lượt cho cùng các chỉ số chất lượng; không đổi rank của file liên quan trong 5 vòng warm.
Đơn vị đánh giá là file đã gán nhãn liên quan, chưa phải tập nhãn đầy đủ để tính recall.

| Nhóm | Số câu | Hit@1 | Hit@5 | MRR@5 |
| --- | ---: | ---: | ---: | ---: |
| Symbol chính xác | 8 | 8/8 | 8/8 | 1,000 |
| Câu hỏi tiếng Anh | 8 | 2/8 | 7/8 | 0,5625 |
| Câu hỏi tiếng Việt | 8 | 8/8 | 8/8 | 1,000 |
| Log giả lập | 4 | 0/4 | 0/4 | 0,000 |
| Tổng positive | 28 | 18/28 (64,3%) | 23/28 (82,1%) | 0,7321 |

Negative: 2/2 marker không tồn tại trả rỗng, 1/2 câu tự nhiên không liên quan trả
rỗng. Câu “diệp lục quang hợp lá cây” vẫn trả kết quả. BM25 với OR không cung cấp
khả năng xác định “không có câu trả lời”.

Câu tiếng Anh bỏ lỡ là `warm pool discard used virtual machines`; top 1 là
`README.md`, không nằm trong nhãn đã khóa. Với `stdout budget exceeded`, top 1
là code trong `crates/sandbox-client/src/wire.rs`, còn file log không có trong top 5.
Đây là kết quả của query DSL cố định, gộp hai index và boost `name^5`, `defs^3`,
`title^2`; chưa đánh giá cách chọn index theo ý định, lọc trường hay Xerj CLI/MCP.
Các câu tiếng Việt chủ yếu tìm BRD tiếng Việt; không chứng minh tìm kiếm xuyên ngôn ngữ.

**Độ trễ và chi phí khởi tạo**

Mỗi VM chạy 32 request ở lượt đầu, rồi 160 request ở 5 vòng warm, tổng cộng 576
request hợp lệ. Đo đồng hồ monotonic trong guest quanh HTTP request/response đầy
đủ, với kết nối loopback mới; không dùng riêng trường `took` của server.

| Chỉ số | Lượt 1 | Lượt 2 | Lượt 3 |
| --- | ---: | ---: | ---: |
| Xerj sẵn sàng | 5,64 s | 5,55 s | 5,97 s |
| Index lần đầu | 57,51 s | 55,01 s | 54,91 s |
| Lượt đầu p50 | 17,73 ms | 15,54 ms | 25,69 ms |
| Lượt đầu p95 | 30,85 ms | 30,19 ms | 75,37 ms |
| Lượt đầu max | 279,94 ms | 276,10 ms | 451,76 ms |
| Warm p50 | 11,67 ms | 10,68 ms | 14,40 ms |
| Warm p95 | 20,35 ms | 17,64 ms | 22,95 ms |
| Warm max | 27,80 ms | 23,73 ms | 33,96 ms |

Spawn VM mất 4,30–4,95 s; copy payload 2,68–3,27 s; ghép/giải nén binary
6,62–7,73 s, được ghi riêng. Biên dịch Cargo release lần đầu mất 27 phút 21 giây
trong Docker với 6 CPU và giới hạn 16 GiB; thời gian này không nằm trong search.
Lượt query đầu đã theo sau indexing và đọc metadata, nên không gọi là cold disk.
Số đo không bao gồm IPC host, MCP, reranking hay sinh câu trả lời.

**RAM và dung lượng**

| RAM, đơn vị MiB | Lượt 1 | Lượt 2 | Lượt 3 |
| --- | ---: | ---: | ---: |
| Server VmHWM trong toàn lượt | 269,70 | 268,54 | 261,11 |
| Server RSS đỉnh quan sát lúc query | 201,49 | 194,38 | 194,48 |
| Indexer VmHWM đỉnh quan sát | 130,77 | 131,29 | 130,58 |
| Server + indexer RSS cùng mẫu, cao nhất | 394,96 | 393,93 | 383,72 |
| Guest MemAvailable thấp nhất | 534,59 | 534,92 | 540,71 |
| QEMU peak working set trên host | 694,87 | 692,77 | 680,95 |

Guest được lấy mẫu mỗi 200 ms, host mỗi 500 ms; VmHWM/peak working set dùng bộ
đếm đỉnh của OS. Tổng RSS hai tiến trình có thể đếm lặp trang dùng chung, và
sampling có thể bỏ lỡ đỉnh cuối rất ngắn của indexer. Guest RAM không được dùng
thay cho RSS host.

| Dung lượng | Kết quả |
| --- | ---: |
| Server data ngay sau index + flush, gồm catalog/metadata | 4,30 MiB logical; 6,60 MiB allocated |
| Server data cuối lượt, sau query và probe | 4,34 MiB logical; 6,64 MiB allocated |
| Autoindex state cuối lượt | 9,36 MiB logical; 9,55 MiB allocated |
| Tổng server data + autoindex state cuối lượt | 16,19 MiB allocated |
| Binary Xerj tĩnh | 153,82 MiB; gzip 37,44 MiB |
| Sandbox host allocation đỉnh | 202,62–223,12 MiB |

Allocated guest là `st_blocks * 512`, sau API flush đã kiểm tra trạng thái shard.
State cuối lượt bao gồm hai probe incremental thất bại. Host allocation còn gồm
binary, corpus, ext4/qcow2 metadata và kết quả đo; không gồm base image dùng chung,
source checkout, Docker build cache hay bản sao evidence ngoài sandbox.

**Thăm dò 256 MiB: chưa hoàn tất index**

Một VM bổ sung dùng 256 MiB guest RAM, giữ nguyên binary, corpus và query. Ở bước
`finalize-verify`, server liên tục trả `circuit_breaking_exception`: read admission
tính cần 135.245.184 byte (129,0 MiB), vượt memory limit tự tính 122.535.116 byte
(116,9 MiB). Log báo sẽ retry tới 600 giây. Sau khoảng bốn phút, người chạy spike
gửi SIGTERM cho đúng tiến trình autoindex, thu evidence và dọn sạch VM.

Đây là lượt chẩn đoán bị dừng chủ động, không phải OOM được quan sát, không phải
lỗi SIGILL và không có số đo chất lượng/latency search hợp lệ. Có các lệnh đọc log
ngắn trong lượt này; không gộp nó vào ba bảng benchmark chính. Kết quả cho thấy
cấu hình 256 MiB với memory governor mặc định chưa hoàn tất được corpus đã thử;
chưa đo mức RAM nhỏ nhất khả dụng, 512 MiB hoặc memory limit điều chỉnh riêng.
[Evidence và lý do dừng](xerj-bm25-tcg-evidence/diagnostic-256m.json).

**Lỗi tương thích CPU đã tái hiện**

Cả `unchanged-index` và `changed-index` đều chết với signal 4 sau khoảng
0,88–1,01 s ở cả 3 VM. File mới không tìm thấy sau đó. Harness lưu lỗi riêng,
đặt `integration_checks_passed=false`, không coi đây là reindex thành công.

Kernel báo invalid opcode tại cùng offset ELF `0xf005b0`. Đối chiếu mapping
executable với [disassembly của đúng binary](xerj-bm25-tcg-evidence/fault-disassembly.txt)
cho thấy lệnh `pmaddubsw`. Guest CPU không có cờ `ssse3`; intrinsic tương ứng
yêu cầu SSSE3 theo [tài liệu Rust](https://doc.rust-lang.org/core/arch/x86_64/fn._mm_maddubs_epi16.html).
Đây là bằng chứng lỗi đường chạy SIMD trên baseline TCG đang thử, dù đã build
với `target-cpu=x86-64`. Chưa quy lỗi tới crate/call site cụ thể vì binary đã strip;
chưa đo cấu hình CPU có SSSE3. Không suy rộng lỗi sang mọi bản phát hành Xerj.

**Quyết định kỹ thuật sau spike**

Giữ Xerj ở mức thử nghiệm tùy chọn. Điều kiện để cân nhắc adapter guest tiếp theo:

1. Chốt CPU baseline và làm các đường index/reindex/search chạy ổn định trên TCG;
   giữ source/binary được ghim và kiểm tra đầy đủ CPU feature cần dùng.
2. Đánh giá chọn index theo loại truy vấn, đặc biệt log; so sánh với search hiện tại
   trên tập nhãn lớn hơn, không điều chỉnh nhãn của spike này để tăng điểm.
3. Đo corpus lớn, RAM thấp, nhiều sandbox đồng thời và chi phí duy trì index trước
   khi chọn cách phân phối binary 154 MiB hoặc giữ server chạy lâu dài.

Nếu tiếp tục, adapter/search tool nên nằm ở tầng ngoài và thực thi trong guest
qua API sẵn có. Spike không cho thấy nhu cầu thay đổi `RuntimeManager` hay đưa
search engine vào `sandbox-core`/`sandbox-protocol`.

Raw của 3 lượt chính nằm trong `.cache/xerj-spike/runs/20261128T185803Z-1024m`;
[manifest SHA-256](xerj-bm25-tcg-evidence/raw-manifest-1024m.json) giữ dấu vết toàn bộ
raw. Evidence trong Git gồm summary, nhãn/corpus, timing, RAM, mapping, flush,
log crash và CPU flags. Các lượt sửa harness trước đó không nhập vào bảng chính;
không thay query hay nhãn sau khi xem kết quả.

Kiểm tra harness: 4 Python unit test và 2 Rust guest unit test đều qua;
`cargo check --all-targets` qua. Ba lượt benchmark chính có đầy đủ timing và
response hợp lệ; cả ba vẫn có `integration_checks_passed=false` vì lỗi incremental.
Lượt 256 MiB được giữ riêng dưới trạng thái incomplete, với `AllResourcesCleaned`.

Giới hạn: một host, corpus nhỏ, câu hỏi do người viết spike gán nhãn, không cố định
xung nhịp/độc chiếm host; chưa có baseline so sánh, chưa đo KVM/HVF/WHPX hay workload
đa tenant. Không chạy full `cargo test --workspace` vì đây là task spike, không
phải cổng chốt Phase; chưa xác nhận tính sẵn sàng tích hợp sản phẩm.
