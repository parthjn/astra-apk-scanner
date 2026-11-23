# Ablation experiment — 20261123-131728

- App ground truth: `./data/ground_truth/insecureshop.yaml`
- Teacher: `gemini-3.6-flash`  Student: `gemini:gemini-3.1-flash-lite`
- Match: `taxonomy`  Repeats/arm: **3**
- Lessons source: `distilled`

## Recall by arm (mean ± sd over repeats)

| Arm | Mean recall | Std dev | Min | Max | Δ vs baseline | Samples |
|---|---|---|---|---|---|---|
| baseline | 42.1% | 0.0% | 42% | 42% | — | 42%, 42%, 42% |
| control | 57.9% | 0.0% | 58% | 58% | +15.8% | 58%, 58%, 58% |
| lessons | 52.6% | 0.0% | 53% | 53% | +10.5% | 53%, 53%, 53% |

_Teacher recall (reference): 57.9% from 13 findings._

## Distilled lessons (accepted)

1. Exported activities or receivers that extract a nested Intent from extras and pass it directly to startActivity enable Intent Redirection vulnerabilities; search for getParcelableExtra or getIntent calls followed by startActivity.
2. Validating domain URLs using string suffix methods like endsWith() allows host verification bypass via rogue domains registered with matching suffixes; search for host or URL checks relying on endsWith() instead of strict Uri parsing.
3. Enabling setAllowUniversalAccessFromFileURLs(true) on WebViews allows local HTML or JavaScript files to bypass same-origin policies and read sensitive local files or cross-origin data; search for setAllowUniversalAccessFromFileURLs or setAllowFileAccessFromFileURLs set to true.
4. Logging sensitive information such as usernames, passwords, or session tokens via Android Log functions exposes secrets to system log output; search for Log calls containing credential variable names.
5. Creating package contexts for external app packages using createPackageContext() and loading classes dynamically via reflection can lead to arbitrary code execution; search for createPackageContext combined with dynamic ClassLoader reflection calls.
6. Embedding cloud identity pool IDs, secret keys, or API tokens in resource XML files or code exposes backend resources to unauthorized access via decompilation; search string resources and source code for embedded service credentials.
7. Overriding onReceivedSslError in a custom WebViewClient to call handler.proceed() disables SSL certificate validation and enables MitM interception; search for WebViewClient implementations calling handler.proceed().
8. Exporting ContentProvider components whose query() method returns sensitive stored credentials via Cursor objects exposes data to unauthorized third-party applications; audit exported content providers for sensitive data exposure in query().
9. Sending implicit broadcasts containing sensitive extras allows malicious applications listening to the intent action to intercept the payload; search for sendBroadcast calls lacking explicit target package names or permission restrictions.
10. Passing getIntent() directly into setResult() inside exported activities can leak internal Intent structures or sensitive data back to calling applications; search for setResult calls using getIntent() directly.

### Rejected by generality guard (instance-specific)

- Setting android:usesCleartextTraffic to true in AndroidManifest.xml permits unencrypted HTTP network communications, exposing app traffic to Man-in-the-Middle eavesdropping; search AndroidManifest.xml for cleartext traffic enablement.
- Hardcoding user credentials or static authentication strings directly in code source files allows simple extraction via reverse engineering; search code for static string definitions containing passwords or API secrets.

## Control checklist (generic, used in the `control` arm)

1. Review every exported component (activity, service, receiver, provider) and confirm it enforces an appropriate permission.
2. Validate and sanitize all data received from Intents, extras, and deep links before use.
3. Ensure sensitive data (credentials, tokens, PII) is encrypted at rest and never written to logs.
4. Verify TLS certificate and hostname validation is never disabled or bypassed.
5. Check WebView configuration for unsafe settings such as JavaScript, file access, or universal access from file URLs.
6. Audit ContentProviders and FileProviders for over-broad access and missing access control.
7. Look for hardcoded secrets, credentials, API keys, or cloud configuration in code and resources.
8. Ensure broadcasts and intents carrying sensitive data are explicit and permission-protected, not implicit.
