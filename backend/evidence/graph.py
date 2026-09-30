"""Evidence graph + correlation engine.

REAL IMPLEMENTATION of the data model; correlation RULES are explicit and
explainable (no black-box scoring).

Node types: Dataset, Contributor, Batch, Sample, Model, ModelVersion,
            Stream, InferenceRecord, ObservationWindow, Finding, Evidence,
            Case, AttackScenario, AssuranceCore
Edge types: contributed_by, belongs_to, produced_by, affects, correlates_with,
            derived_from, violates, verified_by

Every edge is created from an actual relationship in our data (provenance
metadata, registry lineage, record bindings, or a correlation rule whose
reason is stored on the edge).
"""
from __future__ import annotations

import json
from collections import defaultdict
from typing import Any

from ..store import Store


class EvidenceGraph:
    def __init__(self):
        self.nodes: dict[str, dict] = {}
        self.edges: list[dict] = []
        self._edge_keys: set[tuple] = set()

    def node(self, nid: str, ntype: str, label: str, **props: Any) -> str:
        if nid in self.nodes:
            self.nodes[nid]["props"].update(props)
        else:
            self.nodes[nid] = {"id": nid, "type": ntype, "label": label, "props": dict(props)}
        return nid

    def edge(self, src: str, dst: str, rel: str, **props: Any) -> None:
        key = (src, dst, rel)
        if src == dst or key in self._edge_keys or src not in self.nodes or dst not in self.nodes:
            return
        self._edge_keys.add(key)
        self.edges.append({"source": src, "target": dst, "rel": rel, "props": props})

    def ensure_asset(self, nid: str) -> str | None:
        """Create a node for an asset reference like 'batch:batch-17' if it doesn't exist yet."""
        if nid in self.nodes:
            return nid
        kind, _, name = nid.partition(":")
        types = {"dataset": "Dataset", "contributor": "Contributor", "batch": "Batch", "sample": "Sample",
                 "model": "Model", "modelver": "ModelVersion", "inference": "InferenceRecord",
                 "stream": "Stream", "window": "ObservationWindow"}
        if kind not in types:
            return None
        return self.node(nid, types[kind], name)

    # ------------------------------------------------------------ persistence
    def save(self, store: Store, run_id: str) -> None:
        store.execute("DELETE FROM graph_nodes WHERE run_id=?", (run_id,))
        store.execute("DELETE FROM graph_edges WHERE run_id=?", (run_id,))
        with store._lock:
            store.conn.executemany("INSERT INTO graph_nodes(run_id, id, type, label, props) VALUES(?,?,?,?,?)",
                                   [(run_id, n["id"], n["type"], n["label"], json.dumps(n["props"])) for n in self.nodes.values()])
            store.conn.executemany("INSERT INTO graph_edges(run_id, src, dst, rel, props) VALUES(?,?,?,?,?)",
                                   [(run_id, e["source"], e["target"], e["rel"], json.dumps(e["props"])) for e in self.edges])
            store.conn.commit()

    @staticmethod
    def load(store: Store, run_id: str) -> dict:
        nodes = [{"id": r["id"], "type": r["type"], "label": r["label"], "props": json.loads(r["props"] or "{}")}
                 for r in store.query("SELECT * FROM graph_nodes WHERE run_id=?", (run_id,))]
        edges = [{"source": r["src"], "target": r["dst"], "rel": r["rel"], "props": json.loads(r["props"] or "{}")}
                 for r in store.query("SELECT * FROM graph_edges WHERE run_id=?", (run_id,))]
        return {"nodes": nodes, "edges": edges}


def subgraph(graph: dict, seeds: set[str], hops: int = 2) -> dict:
    adj = defaultdict(set)
    for e in graph["edges"]:
        adj[e["source"]].add(e["target"])
        adj[e["target"]].add(e["source"])
    keep = set(seeds)
    frontier = set(seeds)
    for _ in range(hops):
        nxt = set()
        for n in frontier:
            nxt |= adj[n]
        # do not expand through very generic hub nodes
        frontier = {n for n in nxt - keep if not n.startswith(("dataset:", "stream:", "assurance:"))}
        keep |= nxt
    return {"nodes": [n for n in graph["nodes"] if n["id"] in keep],
            "edges": [e for e in graph["edges"] if e["source"] in keep and e["target"] in keep]}


# ====================================================================== correlation rules
def correlate(findings: list[dict]) -> list[dict]:
    """Return correlation links between findings: {a, b, strength, rule, reason}.

    strong   : share specific, independent evidence (same source batch, same trigger
               location, model trained on the implicated source)
    context  : affect the same pipeline component, but no evidence of a causal link
    """
    links: list[dict] = []

    def add(a, b, strength, rule, reason):
        if a["id"] == b["id"]:
            return
        if any({l["a"], l["b"]} == {a["id"], b["id"]} for l in links):
            return
        links.append({"a": a["id"], "b": b["id"], "strength": strength, "rule": rule, "reason": reason})

    def trig(f):
        return (f.get("tags") or {}).get("trigger")

    def near(t1, t2):
        return t1 and t2 and abs(t1["x"] - t2["x"]) <= 2 and abs(t1["y"] - t2["y"]) <= 2

    for i, a in enumerate(findings):
        for b in findings[i + 1:]:
            ta, tb = a.get("tags") or {}, b.get("tags") or {}
            # R1 same data source (contributor/batch) flagged by independent detectors
            if a["pillar"] == b["pillar"] == "dataset" and ta.get("primary_source") and \
                    ta.get("primary_source") == tb.get("primary_source"):
                add(a, b, "strong", "R1-same-source",
                    f"both findings implicate the same source {ta['primary_source']} via independent detectors")
            # R2 same trigger location across pillars (data <-> model <-> operational inputs)
            if a["pillar"] != b["pillar"] and near(trig(a), trig(b)):
                add(a, b, "strong", "R2-same-trigger",
                    f"same trigger location ({trig(a)['x']},{trig(a)['y']}) found independently in "
                    f"{a['pillar']} and {b['pillar']} analysis")
            # R3 model backdoor test used a candidate from a flagged data source
            for x, y in ((a, b), (b, a)):
                tx, ty = x.get("tags") or {}, y.get("tags") or {}
                if x["category"] == "model.backdoor_behaviour" and tx.get("candidate_source") and \
                        tx["candidate_source"] in (ty.get("sources") or []):
                    add(x, y, "strong", "R3-data-to-model",
                        f"the trigger that changes model behaviour was extracted from source {tx['candidate_source']}")
                # R4 model lineage includes a flagged source
                if x["pillar"] == "model" and set(tx.get("lineage_sources") or []) & \
                        {str(s).split("/")[-1] for s in (ty.get("sources") or [])}:
                    add(x, y, "strong", "R4-lineage",
                        "the deployed model version was trained on data that includes the flagged source")
            # R5 inference failures bound to an unregistered/substituted model digest
            if {a["pillar"], b["pillar"]} == {"model", "inference"}:
                da = ta.get("model_digest") or tb.get("model_digest")
                db = tb.get("record_model_digests") or ta.get("record_model_digests")
                if da and db and da in db:
                    add(a, b, "strong", "R5-model-binding",
                        "inference records are cryptographically bound to the substituted model digest")
    # R6 a replaced record breaks the chain link of its successor
    for a in findings:
        for b in findings:
            if a["category"] == "inference.record_replacement" and b["category"] == "inference.chain_broken":
                sa = set((a.get("tags") or {}).get("record_seqs") or [])
                sb = set((b.get("tags") or {}).get("record_seqs") or [])
                if {s + 1 for s in sa} & sb:
                    add(a, b, "strong", "R6-chain-successor",
                        "the successor of the replaced record no longer links to it (hash chain)")
    # context links: everything that affects the live pipeline but has no strong link
    strong_ids = {l["a"] for l in links} | {l["b"] for l in links}
    sig = [f for f in findings if f["severity"] not in ("INFO",)]
    for f in sig:
        if f["id"] in strong_ids:
            continue
        anchor = next((g for g in sig if g["id"] != f["id"] and g["id"] in strong_ids), None) or \
            next((g for g in sig if g["id"] != f["id"]), None)
        if anchor:
            add(f, anchor, "context", "R0-same-pipeline",
                "affects the same assured pipeline; no evidence of a causal link")
    return links


def chains(findings: list[dict], links: list[dict]) -> list[list[str]]:
    """Connected components over STRONG links."""
    parent = {f["id"]: f["id"] for f in findings}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for l in links:
        if l["strength"] == "strong":
            parent[find(l["a"])] = find(l["b"])
    groups = defaultdict(list)
    for f in findings:
        groups[find(f["id"])].append(f["id"])
    return sorted(groups.values(), key=len, reverse=True)
