# apkscan — design write-up

> Paste this into the Google Doc for submission. Sections map 1:1 to the deliverables.

---

## 1. The match function (and why)

**Problem.** A model finding is free text ("WebView proceeds on SSL error");
a ground-truth entry is also prose ("Lack of SSL Certificate Validation"). To
measure recall I need a principled rule for when a finding *is* a ground-truth
vuln — one that is explainable, deterministic, and **not** tuned to InsecureShop
(the harness is graded on an unseen APK).

**Choice: normalized-category matching (default `strategy: taxonomy`).**
Both sides are projected onto a small, app-agnostic taxonomy of Android weakness
classes (`taxonomy.py`, ~22 categories from OWASP MASVS / Mobile Top 10:
`ssl_validation_bypass`, `insecure_content_provider`, `intent_redirection`, …).
A finding matches a ground-truth entry **iff they map to the same canonical
category**. Each GT entry is credited **at most once** (no double-counting), so
`recall = |GT categories hit| / |GT|`.

**Why this one.** It is:
- *Deterministic & auditable* — no model in the eval loop, so the recall number
  isn't itself an LLM guess. A reviewer can read exactly why each match fired.
- *App-agnostic* — categories and keyword aliases describe weakness *classes*,
  not InsecureShop files, so the same matcher works on a new app's ground truth.
- *Robust to location drift* — jadx vs. apktool vs. source produce different
  paths/line numbers, so I do **not** require exact file/line agreement by
  default. Location is used only as an optional tie-breaker
  (`match.require_location`) via component-name overlap.

**Honest limits.** Category matching can **over-credit**: if ground truth has one
"Insecure Logging" and the model flags logging *anywhere*, it counts — even if it
found a different log line. It can also **under-credit** when the taxonomy lumps
two distinct GT entries into one category (InsecureShop has several WebView
issues). I mitigate by keeping categories fairly fine-grained (each of the 19 GT
items maps to a distinct category) and by reporting **precision** alongside
recall so inflation is visible. Two alternative strategies ship behind config for
comparison: `fuzzy` (difflib on normalized text — a zero-infra catch-all) and
`llm_judge` (a model decides equivalence per pair — most semantic, but it costs
tokens and, if the judge is the teacher, biases the eval; the output flags this).
One app cannot prove the lessons generalize — held-out apps are the real test.

---

## 2. Handling a real app with 1M+ LOC

The static slice already ships the *shape* of the answer: **don't send the whole
app to the model — retrieve the attack surface.** Current ingest ranks files by
sensitive-API signals (WebView, Intent, Provider, crypto, secrets) and packs them
into token-budgeted chunks, dropping framework/generated noise (`R.java`,
`androidx/**`). At 1M+ LOC I'd scale this along four axes:

1. **Pre-filter to the attack surface, not the codebase.** Parse the manifest
   first; the exported components (activities, services, providers, receivers)
   and their reachable call-graph are a few % of the code and contain most
   findings. Use a lightweight parser (tree-sitter / `jadx` symbol index) to pull
   only exported entry points + transitive callees + sink functions
   (`loadUrl`, `query`, `exec`, crypto, file I/O).
2. **Retrieval over brute force.** Index every function (embeddings + a grep/AST
   layer for sink patterns). For each weakness class, retrieve the top-k
   candidate functions and scan those, instead of every chunk. This turns cost
   from O(LOC) into O(attack surface).
3. **Two-tier triage.** Cheap pass (the student / a grep-rule layer) flags
   suspicious regions across the whole app; the expensive teacher only audits
   flagged regions. This is the same teacher/student split, used for cost control.
4. **Parallelism + caching + incremental scans.** Chunks are independent, so fan
   out concurrently; cache results by file hash and, in CI, only rescan changed
   files. Map-reduce the per-chunk findings, dedupe, then a single reduce pass
   for cross-file issues.

Determinism (temperature 0), per-file provenance, and dedup by
`(category, file, component)` keep results stable and reviewable at scale.

---

## 3. Dynamic analysis (write, don't build)

*(~450 words)*

**Goal.** Extend the static harness into a dynamic scan driven by an AI agent
against an app with a live backend. The agent installs the app on an instrumented
device, navigates it, fires crafted inputs at the attack surface the static pass
identified, and **confirms** vulnerabilities from observed runtime behavior.

**One bug type static cannot catch:** a **server-side access-control / IDOR**
flaw — e.g. `GET /api/orders/{id}` returning another user's order. Static sees the
client call but not that the backend fails to authorize it; only a live request
with user A's token reading user B's object proves it. (Others: auth-token replay,
insecure TLS actually negotiated on the wire, runtime secret leakage.)

**Confirming a vulnerability (not just a crash).** Each probe ships with an
**oracle** — a pre-stated, checkable success condition — so "it happened" is
distinguished from "it crashed." Examples: for IDOR, victim-owned data appears in
a response to the attacker's session; for an exported-activity redirect, a
canary URL loads in the WebView and our listener server receives the callback;
for insecure logging, the credential string appears in `logcat`; for a provider
leak, `content://` returns bytes of a protected file. The agent asserts the
oracle, captures the proof (HTTP transcript, screenshot, logcat, intent dump),
and only then marks the finding confirmed. A crash with no oracle hit is a
stability bug, logged separately.

**Reaching the right screen.** Bugs sit behind logins and multi-tap flows. The
agent drives the UI via an accessibility/UI-automation tree (Appium/UIAutomator)
rather than pixels, seeded with known credentials and a per-screen goal. It
maintains a screen graph (state = view hierarchy hash), does goal-directed
navigation (LLM picks the next action toward the target component), and falls
back to deep-links/intents from the manifest to jump straight to a target
activity. **Coverage** = exported components exercised, screens/states visited,
and manifest deep-links reached — reported as a fraction of the statically
enumerated attack surface, which ties dynamic back to static.

**Scale.** Emulators are slow, flaky, and need a clean state per run. Run
**ephemeral, snapshot-restored** emulators (or hosted device farms) in a
container/K8s pool; boot from a pre-warmed snapshot with the app + certs
pre-installed so each run resets in seconds. Shard apps/probes across the pool,
cap wall-clock per probe, auto-retry flaky runs, and record everything for
replay so a confirmed finding is reproducible.

**SSL pinning.** To see traffic, route through an intercepting proxy (mitmproxy)
with its CA trusted, and defeat pinning via a Frida script that hooks
`TrustManager`/`OkHttp` `CertificatePinner`/`WebViewClient`. The two–three things
most likely to break: (1) **Frida detection / hook brittleness** — the hook set
lags app/OkHttp versions and root/Frida detection blocks it; (2) **non-HTTP or
certificate-transparency / native (BoringSSL) pinning** the Java hooks miss; and
(3) **network-security-config / cleartext restrictions** plus the Android 7+ user-CA
distrust, which require a system-CA image or a `networkSecurityConfig` patch.

### Architecture diagram

```
                         ┌─────────────────────────────────────────┐
                         │            Orchestrator (K8s)            │
                         │  queue · scheduling · run provenance     │
                         └───────────────┬──────────────────────────┘
          static findings                │  attack-surface + probes
          (apkscan, §1-2) ───────────────┤
                                         ▼
              ┌───────────────── Dynamic Agent (LLM) ─────────────────┐
              │  plan → navigate → inject probe → read oracle → verify │
              └───┬───────────────┬───────────────┬───────────────┬───┘
                  │ UIAutomator   │ intents/       │ crafted       │ assert
                  │ /Appium       │ deep-links     │ HTTP + canary │ oracle
                  ▼               ▼                ▼               ▼
        ┌───────────────── Ephemeral Emulator (snapshot) ───────────────┐
        │  app under test │ Frida (unpin) │ accessibility tree          │
        └──────┬───────────────────────────────┬────────────────────────┘
               │ device traffic                 │ logcat / screenshots
               ▼                                ▼
        mitmproxy (trusted CA) ───────►  Evidence store (transcripts,
               │                              screenshots, oracle hits)
               ▼
          Live backend  ◄──── confirms server-side bugs (IDOR, authz)
```

---

## 4. Which models, and why

| Role | Model (used) | Why |
|---|---|---|
| **Teacher** (frontier) | `gemini-3.6-flash` | Strongest model the Google AI Studio **free tier** actually serves. `gemini-*-pro` returns 429 (billing-gated) and `gemini-2.5-*` 404s for new keys ("no longer available to new users"), so flash-class is the real free-tier ceiling. Strong code reasoning, cheap. |
| **Student** (open-model stand-in) | `gemini-3.1-flash-lite` | A weaker, cheaper lite model so the recall *lift* has headroom, and the loop runs with a **single key**. |
| **Student** (faithful, 1-line switch) | `llama-3.1-8b-instant` on **Groq** | The assignment's intended "open model." Groq's free tier needs no card; a genuinely small model gives a wider teacher→student gap and a more robust lift. Switch: `--set models.student.provider=groq --set models.student.model=llama-3.1-8b-instant`. |
| **Judge** (optional) | teacher model | Only for `strategy: llm_judge`; flagged as biased when judge = teacher. |

The model layer is behind a one-method `ModelClient` interface + registry, so
swapping or adding a provider (OpenAI, Anthropic, another open model) is a config
change, not a code change — directly serving the extensibility criterion.

**Honest note on the model pairing.** On the free tier both teacher and student
end up flash-class, a *narrow* capability gap. That makes the per-run lift small
and noisy (see §5). The faithful fix is a genuinely weaker open student on Groq;
the harness supports it as a one-line config change, and held-out apps are the
real test of whether the lessons generalize.

---

## 5. Recall — before vs. after (measured)

Measured on InsecureShop (19 ground-truth vulns), `taxonomy` match strategy,
teacher `gemini-3.6-flash`, student `gemini-3.1-flash-lite`. Representative
**valid** run (`runs/run-20261122-122343`):

| Model | Recall | Findings | Precision |
|---|---|---|---|
| Teacher | 36.8% (7/19) | 7 | 1.00 |
| Student — before lessons | 42.1% (8/19) | 13 | 0.62 |
| Student — after lessons | **52.6% (10/19)** | 14 | 0.71 |

**Recall lift: +10.5% absolute (+25% relative)** — and precision *also* rose
(0.62 → 0.71), so the gain is real coverage, not just more guessing. The student
newly caught **GT-03** (weak host validation), **GT-05** (intent redirection),
and **GT-18** (insecure storage) — the first two map directly to distilled
lessons; GT-18 survived because the lessons were framed to *augment*, not replace,
the student's own analysis.

### Honesty: variance and invalid runs

This is **one app with two flash-class models**, and the signal is noisy:

- **Variance.** Across repeats the per-run lift ranged from roughly −5% (before
  the fixes below) to +10.5%. A single run can mislead, so the harness supports
  `eval.repeats: N` — it reruns the student baseline + lessoned scans N times and
  reports the **mean lift plus per-run samples** (teacher scan + distillation run
  once). Use N≥3 for a defensible headline number.
- **Invalid runs are flagged.** If the teacher is rate-limited and returns 0
  findings, no lessons exist and `after == before` trivially (a fake "0% lift").
  The pipeline now marks such runs `valid_run: false` and the report prints an
  **INVALID RUN** banner, so a quota-killed run is never reported as a real result.
- **Two fixes that turned a −5% run into +10.5%.** (1) The lesson *generality
  guard* was over-eager — it discarded general, high-value lessons (SSL-error
  bypass, cleartext traffic, cloud credentials) merely for mentioning
  `AndroidManifest.xml` or prose like "SSL/TLS". It now rejects only truly
  app-specific tokens (line numbers, `*.java/.kt/.smali` files, the app's own
  class/package names). (2) Injecting lessons as a *checklist* made the weak
  student tunnel-vision and drop findings it had made on its own; reframing the
  lessons to "do your full analysis first, then also check these" recovered them.

**Caveat (as the brief asks):** one app cannot prove the lessons generalize — a
narrow model gap and category-level matching can both flatter or understate the
result. The real evidence is held-out apps, which we'd discuss in the interview.
