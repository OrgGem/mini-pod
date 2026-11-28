# Xerj BM25 / mini-pod TCG spike

This is a measurement harness, not a product search adapter. It changes no
runtime contracts. Windows hosts need the normal mini-pod QEMU installation,
Docker, Python 3, Rust, and the signed development bundle/public key used by
the existing runtime tests.

The [2026-11-29 measurement report](../../../docs/benchmarks/xerj-bm25-tcg-windows-x86_64.md)
records three 1 GiB TCG runs and a separate 256 MiB diagnostic. Initial search
completed, but incremental indexing hit unsupported SIMD instructions; the
report recommends deferring product integration.

## Pins and isolation

- Xerj public source: `35ccd192508027cccc1b3e69f3b6721cb17cac64`.
- Corpus: mini-pod `e359a799946933c10b2c406d9b30c7a810ab15c2`, regular Rust and
  Markdown files under `crates`, `bins`, `guest`, `docs`, plus BRD and README.
- Four JSONL diagnostic records are **synthetic**, not observed incidents.
- Linux musl executable, `--locked --no-default-features`, release optimization
  with thin LTO / 16 codegen units. Rust target CPU is generic `x86-64` rather
  than upstream's `x86-64-v2`, matching mini-pod's current TCG CPU baseline.
- The builder base is pinned by digest. Exact Rust and Alpine package versions,
  Cargo.lock hash, builder image ID, binary hashes and build flags are recorded.
  Alpine build-tool package downloads are not a reproducible package mirror.
- VM: `VmRequired`, `AccelerationPolicy::SoftwareOnly`, `NetworkPolicy::Isolated`,
  one vCPU, 1024 MiB guest RAM, 2048 MiB host RSS budget, 2048 MiB virtual disk,
  3072 MiB host storage budget. No Warm Pool and no published host ports.
- The host verifies the actual QEMU command has `tcg,tb-size=32` and `-nic none`;
  the guest rejects any interface other than loopback. Source fetching/building
  uses the network on the host. All index/query measurements run offline in VM.
- Xerj is a copied workload, checked by SHA-256 in the guest. The base VM bundle
  remains signed; this spike does not change the production bundle.
- Xerj's server and indexer inherit the exec process group. The guest driver
  owns their lifetime, and mini-pod destroys the entire VM in a `finally` block.

## Run

From the repository root in PowerShell:

```powershell
cargo build --release -p sandboxd -p sandbox-cli
./scripts/benchmarks/xerj/build.ps1
python scripts/benchmarks/xerj/run.py prepare
python scripts/benchmarks/xerj/run.py run --runs 3 --ram-mib 1024
python scripts/benchmarks/xerj/analyze.py .cache/xerj-spike/runs/<run-directory>
```

`run.py` currently selects `.cache/bundles-perf/8c7be5d/x86_64` and
`.cache/keys/dev-bundle.pub`, the existing local signed fixture. Its manifest
hash is recorded; adapt these two paths to another signed fixture explicitly.
Source, binary, Docker build volume, payload, raw responses, logs and state live
outside Git under `.cache/xerj-spike` (Docker volume `minipod-xerj-build-35ccd192`).
No public release binary or proprietary Query-1 model is used.
The executable is gzip-compressed and copied in 8 MiB pieces to respect the
current CLI's 16 MiB per-copy cap. The guest reassembles and decompresses it,
then verifies its SHA-256 before starting measurements. Transfer and unpack
times are recorded separately from indexing and search latency.

## Protocol

The 32 queries and relevant file paths are fixed **before querying** and their
hash is recorded. There are 28 positive known-item questions (8 symbol, 8 English,
8 Vietnamese, 4 synthetic-log) and 4 negatives. The Vietnamese questions mostly
target the Vietnamese BRD; this is not a cross-language semantic benchmark.

`autoindex --no-semantic --no-graph --workers 1 --plan no-vectors` indexes the
corpus. Queries use the same fixed `multi_match` BM25 body with `name^5`,
`defs^3`, `title^2`, `body`, `text`, `code`, and `message`, `best_fields`, OR,
and five hits. This is direct engine retrieval, not the mapping-aware Xerj CLI,
MCP, reranking, graph retrieval, or answer generation.

Each fresh VM performs one initial index, one first pass of all questions, five
warm rounds with a rotating order, an unchanged reindex, and a new-file freshness
probe. HTTP failures, partial shards and timed-out results are errors, never
relabelled as misses. Quality uses file hit@1, file hit@5, MRR@5 and negative
empty-result counts. Labels are known relevant files, not exhaustive relevance
judgements, so this is not recall@5. Repeated rounds are latency samples, not
additional independent quality questions.
Incremental-index probes run after the frozen search set. Their failures are
retained in `probes.tsv` and make `integration_checks_passed` false; they do not
erase valid initial-index/query measurements or count as successful reindexing.

Latency is measured by the guest's monotonic clock around a complete local HTTP
request/response using a new loopback connection. It includes JSON response
transfer, excludes host IPC and process startup, and does not rely on the
engine's `took` field. First pass is not a cold-disk guarantee: indexing and
metadata reads already touched the data. Percentiles use nearest rank.

RAM has separate measures: server `/proc/<pid>/status` VmHWM, server/indexer RSS
sampled every 200 ms, guest MemAvailable, and Windows QEMU working set sampled
every 500 ms (plus the OS peak working set). The indexer's observed HWM can miss
a final short peak. Summed process RSS double-counts shared pages. Neither guest
RSS nor allocated guest RAM is presented as host RSS.

Storage includes actual allocated guest blocks (`st_blocks * 512`) and logical
bytes, with server data and autoindex state separate. Host physical allocation
uses `GetCompressedFileSizeW`; its sandbox total also includes the payload, ext4
overhead, output evidence and qcow2 metadata. A cleanup must report
`AllResourcesCleaned` with no remaining sandbox overlay.
Storage snapshots follow `POST /_flush`, whose shard status is checked. The
pinned server's per-index flush route does not expand `spike-*` wildcards.

## Harness checks

```powershell
python -m unittest discover -s scripts/benchmarks/xerj -p test_harness.py -v
cargo check --all-targets
```

`build.ps1` also builds/runs two std-only Rust tests for the guest HTTP and memory
parsers. The HTTP reader deliberately rejects chunked framing and oversized,
truncated or error responses rather than accidentally measuring corrupt data.

This spike does not establish production capacity, multi-tenant authorization,
host filesystem indexing safety, neural retrieval quality, or cross-platform
performance. Compare its resource cost and misses before deciding on integration.
