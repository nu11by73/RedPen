"""Batch execution engine."""
from __future__ import annotations
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Callable, Optional
from connectors import TargetConfig, send_prompt, TargetError
from mutations import generate_variants
from judge import judge_response


@dataclass
class BatchItem:
    payload_id: str
    owasp: str
    atlas: str
    technique: str
    severity: str
    payload: str
    success_signal: str


def run_batch(items, target_cfg, judge_cfg, mutations,
              delay_sec=1.0, progress_cb=None, save_cb=None):
    results = []
    total_units = sum(1 + len(mutations) for _ in items)
    done = 0

    for item in items:
        variants = generate_variants(item.payload, mutations)
        for mname, ptext in variants:
            if progress_cb:
                progress_cb(done, total_units, f"{item.payload_id} [{mname}]")

            try:
                response = send_prompt(target_cfg, ptext)
                err = None
            except TargetError as e:
                response = ""; err = str(e)
            except Exception as e:
                response = ""; err = f"unexpected: {e}"

            if judge_cfg and response and not err:
                verdict_obj = judge_response(judge_cfg, ptext,
                                             item.success_signal, response)
            else:
                verdict_obj = {"verdict": "error" if err else "inconclusive",
                               "confidence": 0.0,
                               "rationale": err or "no judge configured"}

            outcome_map = {"bypass": "Bypass (success)",
                           "partial": "Partial bypass",
                           "blocked": "Blocked",
                           "inconclusive": "Inconclusive",
                           "error": "Error"}

            row = {
                "ts": datetime.utcnow().isoformat(timespec="seconds"),
                "payload_id": f"{item.payload_id}/{mname}",
                "owasp": item.owasp, "atlas": item.atlas,
                "technique": f"{item.technique} ({mname})",
                "severity": item.severity,
                "target": f"{target_cfg.kind}:{target_cfg.model}",
                "payload": ptext, "response": response or (err or ""),
                "outcome": outcome_map.get(verdict_obj["verdict"], "Inconclusive"),
                "notes": (f"judge_conf={verdict_obj.get('confidence')} | "
                          f"{verdict_obj.get('rationale','')}"),
            }
            results.append(row)
            if save_cb:
                save_cb(row)
            done += 1
            time.sleep(delay_sec)

    if progress_cb:
        progress_cb(total_units, total_units, "done")
    return results