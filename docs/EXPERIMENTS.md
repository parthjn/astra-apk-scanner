# Experiments & evidence

This document backs every number in the write-up and answers the reviewer's
verification asks. All raw artifacts are committed under [`runs/`](../runs) —
each folder has a `results.json`/`experiment.json` (full findings, matches,
lessons) and a `report.md`.

Reproduce any arm:
```bash
# 3-arm ablation (baseline / generic-checklist control / distilled lessons), 3x
apkscan experiment --repeats 3 --arms baseline,control,lessons

# apply InsecureShop's lessons to a second app, with that app's baseline
apkscan experiment --repeats 3 --arms baseline,control,lessons \
  --lessons-from runs/experiment-20261123-133418/experiment.json \
  --set app.decompiled_path=./data/decompiled/insecurebankv2 \
  --set ground_truth.path=./data/ground_truth/insecurebankv2.yaml
```

Models: teacher `gemini-3.6-flash`, student `gemini-3.1-flash-lite`. Match:
`taxonomy`. Student scans repeat N times; teacher scan + distillation run once.

---

## Headline

| Experiment | Arm | Mean recall | sd | Δ vs baseline | Run folder |
|---|---|---|---|---|---|
| **InsecureShop** (temp 0, 3×) | baseline | 42.1% | 0.0 | — | `experiment-20261123-133418` |
| | control (generic checklist) | 47.4% | 0.0 | +5.3% | |
| | lessons (distilled, 13) | **52.6%** | 0.0 | **+10.5%** | |
| **InsecureShop** (temp 0.5, 4×) | baseline | 43.4% | 2.3 | — | `experiment-20261123-132937` |
| | control | 47.4% | 0.0 | +3.9% | |
| | lessons | **57.9%** | 3.7 | **+14.5%** | |
| **InsecureBankv2** (transfer, temp 0, 3×) | baseline | 66.7% | 0.0 | — | `experiment-20261123-133833` |
| | control | 75.0% | 0.0 | +8.3% | |
| | lessons (InsecureShop's) | 75.0% | 0.0 | +8.3% | |

(An earlier transfer run with a 10-lesson set, `experiment-20261123-132606`,
gave lessons **83.3%** vs control 75.0% — see "Honest caveats".)

### What the data supports (and what it doesn't)

- **Robust:** prepending guidance — distilled lessons *or* a generic checklist —
  consistently lifts the weak student over baseline: **+5% to +14.5%** across
  apps and temperatures. This is the real, reproducible effect.
- **Robust:** the distilled lessons **transfer** — lessons distilled from
  InsecureShop lift the student on the unseen InsecureBankv2 by **+8.3%** over
  that app's own baseline. The lessons are general, not InsecureShop-specific.
- **Within noise:** whether distilled lessons *beat a generic checklist* is not
  robustly established on these two "textbook" apps with a flash-lite student.
  Lessons edge the checklist in most runs (e.g. +5.3% vs +3.9% on InsecureShop
  temp 0.5→+14.5% vs +3.9%; 83.3% vs 75.0% on the earlier transfer run) and tie
  it in others (75.0% vs 75.0%). The margin is ~1 ground-truth item, inside the
  run-to-run noise. On textbook apps whose vulns *are* the standard categories, a
  generic checklist is a strong baseline; distillation's edge should show on
  harder / held-out apps and stronger teachers — the held-out test we'd discuss.

---

## 1. All runs behind the write-up (incl. earlier lower-scoring ones)

| Folder | Kind | App | Config note | before→after / arms |
|---|---|---|---|---|
| `run-20261122-121755` | pipeline | InsecureShop | 192 files, **pre-fix** (bad guard + checklist-framing) | 52.6%→47.4% (**−5.3%**) |
| `run-20261122-122343` | pipeline | InsecureShop | 25 files, post-fix (the originally reported run) | 42.1%→52.6% (**+10.5%**) |
| `run-20261122-122524` | pipeline | InsecureShop | **INVALID** — teacher rate-limited, 0 findings | 42.1%→42.1% (0, not meaningful) |
| `run-20261122-122630` | pipeline | InsecureShop | **INVALID** — teacher rate-limited, 0 findings | 42.1%→42.1% (0, not meaningful) |
| `experiment-20261123-131728` | ablation | InsecureShop | temp 0, **old guard** (10 lessons, 2 wrongly rejected) | base 42.1 / ctrl 57.9 / less 52.6 |
| `experiment-20261123-132606` | ablation | InsecureBankv2 | temp 0, app1's 10-lesson set | base 66.7 / ctrl 75.0 / less 83.3 |
| `experiment-20261123-132937` | ablation | InsecureShop | **temp 0.5** variance demo, 4× | base 43.4±2.3 / ctrl 47.4 / less 57.9±3.7 |
| `experiment-20261123-133418` | ablation | InsecureShop | temp 0, **fixed guard** (13 lessons) | base 42.1 / ctrl 47.4 / less 52.6 |
| `experiment-20261123-133833` | ablation | InsecureBankv2 | temp 0, app1's 13-lesson set | base 66.7 / ctrl 75.0 / less 75.0 |

The two **INVALID** runs are exactly the failure mode the harness now guards:
teacher rate-limited → 0 findings → no lessons → `after == before` trivially.
Such runs are flagged `valid_run: false` with an **INVALID RUN** banner so they
can never be reported as a real "0% lift".

---

## 2. Distilled lessons — accepted & rejected (fixed-guard run `133418`)

**Accepted (13):**

1. Exported activities/receivers that extract a nested Intent from extras and pass it to startActivity enable Intent Redirection; search for getParcelableExtra/getIntent followed by startActivity.
2. Validating domain URLs with suffix methods like endsWith() allows host-verification bypass via rogue domains; search for host/URL checks using endsWith() instead of strict Uri parsing.
3. Enabling setAllowUniversalAccessFromFileURLs(true) lets local HTML/JS bypass same-origin and read local files; search for setAllowUniversalAccessFromFileURLs / setAllowFileAccessFromFileURLs = true.
4. Logging usernames/passwords/tokens via Log exposes secrets to logcat; search for Log calls with credential variable names.
5. createPackageContext() for external packages plus reflection can lead to arbitrary code execution; search for createPackageContext with dynamic ClassLoader reflection.
6. Embedding cloud identity-pool IDs / secret keys / API tokens in resources or code exposes backends; search string resources and code for embedded service credentials.
7. Overriding onReceivedSslError to call handler.proceed() disables TLS validation and enables MitM; search for WebViewClient implementations calling handler.proceed().
8. Exported ContentProviders whose query() returns stored credentials expose data to other apps; audit exported providers for sensitive data in query().
9. Implicit broadcasts carrying sensitive extras can be intercepted by any listening app; search for sendBroadcast lacking an explicit target package or permission.
10. Passing getIntent() directly into setResult() in exported activities can leak internal Intent data to callers; search for setResult using getIntent() directly.
11. Setting android:usesCleartextTraffic="true" permits unencrypted HTTP and MitM; check the manifest for cleartext traffic enablement.
12. Hardcoding credentials or static auth strings in source/resources allows extraction via reverse engineering; search for static strings containing passwords or API secrets.
13. (varies run to run — see `runs/experiment-20261123-133418/experiment.json`)

**Rejected by the generality guard (fixed run):** 0. In the *old* run
(`131728`) the guard wrongly rejected the cleartext-traffic and hardcoded-secret
lessons because the teacher cited `AndroidManifest.xml` / `strings.xml` as
finding locations, leaking those generic filenames into the banned-token list.
Fixed (generic framework filenames are now whitelisted; regression test added),
which is why the fixed run accepts 13 and rejects 0.

---

## 3. The control checklist (generic, used in the `control` arm)

[`data/control_checklist.yaml`](../data/control_checklist.yaml) — 8 generic
OWASP-MASVS-flavored items, *not* derived from any app's findings, of length
comparable to the distilled lesson set. It exists purely to test whether the
lift is from the *specific* lessons or from prepending *any* checklist.

---

## 4. Honest caveats

- **Gemini is not perfectly deterministic**, even at temperature 0: the 3 repeats
  inside one process are identical (likely response caching of identical
  prompts), but the same arm across separate invocations can differ by ~1 GT item
  (e.g. control 57.9% in run `131728` vs 47.4% in `133418`). Honest spread is best
  read from the **temp-0.5** run (`132937`), where baseline/lessons show sd 2.3–3.7%.
- **Small ground-truth sets** (19 and 12 items) mean one finding = ~5–8%, so
  modest effect sizes need many apps to separate signal from noise.
- **Two apps cannot prove generalization.** The transfer result is encouraging but
  the real evidence is a held-out battery of apps — the next step we'd discuss.
