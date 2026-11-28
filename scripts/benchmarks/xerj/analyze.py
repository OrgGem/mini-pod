"""Score frozen known-item labels and summarize measurements without counting repeats as new queries."""
import argparse
import csv
import hashlib
import json
import math
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def rows(path):
    with path.open(encoding="utf-8") as file:
        return list(csv.DictReader(file, delimiter="\t"))


def percentiles(values):
    values = sorted(values)
    if not values:
        raise ValueError("No measurement samples")
    return {"n": len(values), "p50": values[math.ceil(len(values) * 0.50) - 1],
            "p95": values[math.ceil(len(values) * 0.95) - 1], "max": values[-1]}


def normalized_path(source):
    path = source.get("ax_path") or source.get("path")
    if not isinstance(path, str):
        return None
    for prefix in ("/workspace/spike/corpus/", "corpus/"):
        if path.startswith(prefix):
            return path[len(prefix):]
    return path


def score(query, response):
    if "error" in response or response.get("timed_out") or response.get("_shards", {}).get("failed", 0):
        raise ValueError(f"Search failed for {query['id']}; must not score as a miss")
    hits = response["hits"]["hits"]
    paths = [normalized_path(hit.get("_source", {})) for hit in hits]
    rank = next((i + 1 for i, path in enumerate(paths[:5]) if path in query["relevant"]), None)
    return {"id": query["id"], "category": query["category"], "query": query["query"],
            "relevant": query["relevant"], "rank_at_5": rank, "empty": not hits,
            "hits": [{"path": path, "line": hit.get("_source", {}).get("line") or hit.get("_source", {}).get("start_line"),
                      "name": hit.get("_source", {}).get("name"), "score": hit.get("_score"),
                      "index": hit.get("_index"), "id": hit.get("_id")}
                     for hit, path in zip(hits, paths)]}


def quality(items):
    result = {}
    for group in ["all_positive"] + sorted({item["category"] for item in items}):
        part = [i for i in items if (bool(i["relevant"]) if group == "all_positive" else i["category"] == group)]
        if not part:
            continue
        if not part[0]["relevant"]:
            result[group] = {"n": len(part), "empty_results": sum(i["empty"] for i in part)}
        else:
            result[group] = {"n": len(part), "hit_at_1": sum(i["rank_at_5"] == 1 for i in part),
                             "hit_at_5": sum(i["rank_at_5"] is not None for i in part),
                             "mrr_at_5": sum(1 / i["rank_at_5"] if i["rank_at_5"] else 0 for i in part) / len(part)}
    return result


def vector_mapping(value):
    if isinstance(value, dict):
        return value.get("type") in {"dense_vector", "semantic_text"} or any(vector_mapping(v) for v in value.values())
    return isinstance(value, list) and any(vector_mapping(v) for v in value)


def analyze(directory):
    metadata = read_json(directory / "metadata.json")
    queries = read_json(HERE / "queries.json")
    if hashlib.sha256((HERE / "queries.json").read_bytes()).hexdigest() != metadata["manifest"]["queries_sha256"]:
        raise ValueError("Frozen query checksum mismatch")
    result = {"metadata": metadata, "method": "known-item file hit@1/hit@5 and MRR@5; nearest-rank latency percentiles", "runs": []}
    for run in metadata["runs"]:
        if not run.get("completed"):
            raise ValueError("Incomplete run; retain failure evidence separately")
        guest = directory / f"run-{run['run']}" / "guest"
        if vector_mapping(read_json(guest / "mapping.json")):
            raise ValueError("Vector or semantic mapping present in a BM25-only run")
        for name in ("initial-flush", "final-flush", "count"):
            response = read_json(guest / f"{name}.json")
            if "error" in response or response.get("_shards", {}).get("failed", 0):
                raise ValueError(f"Failed {name}: {response}")
        stats = {r["metric"]: float(r["value"]) for r in rows(guest / "measurements.tsv")}
        timings = rows(guest / "queries.tsv")
        if len(timings) != len(queries) * 6:
            raise ValueError("Missing query timing samples")
        scored = [score(q, read_json(guest / f"query-0-{q['id']}.json")) for q in queries]
        rank_changes = 0
        for round_number in range(1, 6):
            for query, first in zip(queries, scored):
                later = score(query, read_json(guest / f"query-{round_number}-{query['id']}.json"))
                rank_changes += later["rank_at_5"] != first["rank_at_5"]
        memory = rows(guest / "memory.tsv")
        host = rows(directory / f"run-{run['run']}" / "host-memory.tsv")
        if run["host_monitor_errors"] or not host or run["destroy_cli_exit_code"] or run["remaining_overlay_count"]:
            raise ValueError("Host measurement or cleanup failed")
        cleanup = json.loads(run["destroy_output"])
        if cleanup.get("status") != "AllResourcesCleaned":
            raise ValueError("Resources were not fully cleaned")
        digest = read_json(directory / f"run-{run['run']}" / "guest-sha256.json")
        if digest.get("exit_code") != 0 or digest.get("stdout", "").split()[0] != metadata["xerj_sha256"]:
            raise ValueError("Guest binary checksum mismatch")
        freshness = read_json(guest / "freshness-added.json")
        fresh = score({"id": "freshness", "category": "check", "query": "sentinel", "relevant": ["freshness.txt"]}, freshness)
        probes = rows(guest / "probes.tsv")
        if {p["probe"] for p in probes} != {"unchanged-index", "changed-index"}:
            raise ValueError("Missing incremental-index probes")
        details = {
            "run": run["run"], "measurements": stats, "quality": quality(scored), "queries": scored,
            "indexed_records": read_json(guest / "count.json")["count"],
            "indices": read_json(guest / "indices.json"),
            "first_pass_ms": percentiles([float(r["elapsed_ms"]) for r in timings if r["round"] == "0"]),
            "warm_ms": percentiles([float(r["elapsed_ms"]) for r in timings if r["round"] != "0"]),
            "warm_category_ms": {category: percentiles([float(r["elapsed_ms"]) for r in timings if r["round"] != "0" and any(q["id"] == r["id"] and q["category"] == category for q in queries)]) for category in sorted({q["category"] for q in queries})},
            "rank_changes_across_warm_rounds": rank_changes,
            "server_peak_hwm_kib": max(int(r["server_hwm_kib"]) for r in memory),
            "server_query_peak_rss_kib": max(int(r["server_rss_kib"]) for r in memory if r["phase"] in {"first_query", "warm_query"}),
            "indexer_observed_peak_hwm_kib": max(int(r["indexer_hwm_kib"]) for r in memory),
            "combined_sampled_peak_rss_kib": max(int(r["server_rss_kib"]) + int(r["indexer_rss_kib"]) for r in memory),
            "guest_min_available_kib": min(int(r["guest_available_kib"]) for r in memory),
            "host_qemu_peak_rss_bytes": max(int(r["qemu_peak_rss_bytes"]) for r in host),
            "host_sandbox_peak_allocated_bytes": max(int(r["sandbox_allocated_bytes"]) for r in host),
            "freshness_added_hit_at_5": fresh["rank_at_5"] is not None,
            "incremental_probes": probes,
            "integration_checks_passed": all(not p["error"] for p in probes) and fresh["rank_at_5"] is not None,
            "bm25_only_mapping_verified": True,
        }
        result["runs"].append(details)
    (directory / "summary.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps([{k: v for k, v in r.items() if k not in {"queries", "warm_category_ms"}} for r in result["runs"]], indent=2))
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("results", type=Path)
    analyze(parser.parse_args().results)
