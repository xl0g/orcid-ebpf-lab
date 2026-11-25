# OrcID — identity-anchored eBPF detection (reproducible lab)

Research lab accompanying the preprint *"eBPF for Real-Time Detection of Sophisticated, AI-Driven Attacks."*
It measures how anchoring an eBPF sensor on **workload identity** (cgroup) affects false positives, runs an
**attack → defense → re-evaluation** study, and compares against a real tool (Tetragon) and a public dataset (ADFA-LD).

> ⚠️ **Authorized security research only.** Everything runs in a closed lab on an internal Docker network with
> **no external reachability**; all "secrets" are fake. The attack scripts replay a single kill-chain objective
> (read a fake secret → exfiltrate to the lab sink) to evaluate a *defense*. Do not run against systems you do
> not own, and do not point exfiltration at any real host.

## Key results (all measured; see `results/*.json`)
| Experiment | Finding |
|---|---|
| Identity anchoring vs false positives | D2 (identity) = 100% detection, **0 FP**; D0/D1 (identity-blind) ≈ 22 FP/min on a benign job |
| Real-tool baseline | **Tetragon** generic policy = **47 benign FP/min**; D3 = **0** |
| Evasion (mimicry over existing HTTP channel) | novelty (D2) **collapses to 0%**; rate rule (D3) restores 100% / 89.6% |
| 16 LLM-authored variants | signature & novelty = **62%**; D3 = **100%** |
| ADFA-LD (public dataset) | STIDE 5-gram novelty, **AUC 0.782** (generalizes but weak alone) |

## Layout
- `sensor/trace.bt` — eBPF (bpftrace) sensor: `execve` / `openat` / `connect` / `sched_process_fork`, tagged by cgroup
- `victim/` — vulnerable web service (the foothold)   ·  `backup/` — legitimate credential-reading job (hard negative)
- `sink/` — collection endpoint   ·  `attacks/loadgen.py` — benign traffic
- `attacks/campaign.py` — polymorphic variants  ·  `attacks/evade.py` — A1/A2/A3 stealth ladder  ·  `attacks/llm_variants.py` — 16 LLM-authored
- `tetragon/policy.yaml` — Tetragon baseline policy
- `analysis/` — detectors (D0/D1/D2/D3), aggregation, evasion & ADFA analysis
- `results/` — JSON result summaries (large raw captures are git-ignored and regenerable)

## Reproduce
```sh
./run_experiment.sh att_7 40 70 40 7 attack      # main experiment, one seed
python3 analysis/aggregate.py                    # -> results/summary.json
./run_class.sh A3h_7 7 A3h                        # one evasion class
python3 analysis/evade_analysis.py               # -> results/evasion.json
```
Kernel used: Docker Desktop linuxkit 6.10.14 (aarch64), BTF present, BPF-LSM enabled, bpftrace v0.20.2.
ADFA-LD is a third-party public dataset; it is **not** redistributed here (download separately).
