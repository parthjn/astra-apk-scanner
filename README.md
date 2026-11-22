# apkscan — teacher→student LLM pipeline for static APK vulnerability scanning

A small, honest end-to-end slice of "teach a frontier model to find Android
vulns, then teach a cheaper open model to match it." Built for the Astra
take-home. It ingests a decompiled app, scans it with a **teacher** (frontier)
model, distills the teacher's findings into **general lessons**, feeds those to a
**student** (open) model, rescans, and **measures the student's recall lift**
against a ground-truth vuln list.

Nothing is hard-coded to a specific app: the app path, models, thresholds, and
ground truth all live in `config/` + `data/`, so the same harness runs on an
unseen APK by editing config only.

## Architecture

```
          config/default.yaml  +  data/ground_truth/<app>.yaml
                                  │
   decompiled app ──► ingest ──► chunks ──► scan(model) ──► findings ──► match ──► recall
   (jadx output)       │                      ▲                           │
                       │                      │ lessons (general rules)   │
                       │          teacher ────┴──► distill ──► [guard] ───┘
                       │          ──────────────────────────────────────────
                       └► loader prioritizes attack-surface files (WebView,
                          Intent, Provider, crypto, secrets) under a token budget
```

Modules (`src/apkscan/`):

| file | role |
|---|---|
| `ingest.py` | load manifest/code/resources, prioritize risky files, chunk |
| `models/` | provider interface + Gemini / Groq / OpenAI / Anthropic / Mock |
| `taxonomy.py` | app-agnostic Android weakness categories (for matching) |
| `scan.py` | run a model over chunks → structured `Finding`s |
| `lessons.py` | teacher → **general** lessons (single pass) + generality guard |
| `match.py` | match findings ↔ ground truth; recall/precision |
| `pipeline.py` | the full teacher→student loop |
| `report.py` | `results.json` + `report.md` per run |
| `cli.py` | `apkscan run / scan / ingest / providers` |

## Quick start

```bash
pip install -e ".[dev]"                   # installs apkscan + deps + pytest
#   (or: pip install -r requirements.txt, but then run via PYTHONPATH=src)
cp .env.example .env                      # add GOOGLE_API_KEY (and GROQ_API_KEY if used)

# 1. Decompile the target APK (needs jadx: brew install jadx)
scripts/decompile.sh https://github.com/hax0rgb/InsecureShop/releases/download/<ver>/InsecureShop.apk insecureshop

# 2. Run the full loop (teacher + student + lessons + recall)
python -m apkscan.cli run -c config/default.yaml
#   artifacts land in runs/run-<timestamp>/{results.json,report.md}
```

### Run offline / verify the logic without any API key
The whole pipeline is covered by tests using a **mock model**:
```bash
pytest -q          # exercises ingest, matching, recall math, lesson guard, full loop
```

## Models used (default)
- **Teacher:** `gemini-3.6-flash` — the strongest model the Google AI Studio
  **free tier** actually serves (`*-pro` is billing-gated 429; `gemini-2.5-*`
  404s for new keys).
- **Student:** `gemini-3.1-flash-lite` by default so the loop runs with **one key**.
  Switch to a genuinely weaker open model (the faithful "student") with no code change:
  ```bash
  python -m apkscan.cli run \
    --set models.student.provider=groq \
    --set models.student.model=llama-3.1-8b-instant
  ```
  (Groq free tier, no card — set `GROQ_API_KEY`.)

## Robust measurement
Small models are noisy run-to-run, so for a defensible number average several runs:
```bash
python -m apkscan.cli run --set eval.repeats=3   # mean lift + per-run samples
```
If the teacher is rate-limited and returns 0 findings, the run is marked
`valid_run: false` and the report prints an **INVALID RUN** banner — a
quota-killed run is never reported as a real "0% lift".

## Running on a new / unseen APK
1. `scripts/decompile.sh <apk> myapp`
2. Write `data/ground_truth/myapp.yaml` (same shape as the InsecureShop file).
3. `python -m apkscan.cli run --set app.decompiled_path=./data/decompiled/myapp \
      --set ground_truth.path=./data/ground_truth/myapp.yaml`

No source edits. Add a whole new model **provider** by dropping a `ModelClient`
subclass in `models/` and one line in `models/registry.py`.

## Design docs
See [`docs/writeup.md`](docs/writeup.md): the match function + rationale, scaling
to 1M+ LOC, the dynamic-analysis design + diagram, and model choices.
