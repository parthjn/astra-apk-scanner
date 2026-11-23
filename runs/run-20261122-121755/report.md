# APK Scan Run — 20261122-121755

- **Teacher:** `gemini:gemini-3.6-flash`
- **Student:** `gemini:gemini-3.1-flash-lite`
- **Match strategy:** `taxonomy`
- **Files scanned:** 192

## Recall (headline)

| Model | Recall | Findings |
|---|---|---|
| Teacher (reference ceiling) | 63.2% | 14 |
| Student — before lessons | 52.6% | 15 |
| Student — after lessons | 47.4% | 14 |

**Recall lift: -5.3% absolute (-10% relative)**

## General lessons used

1. Components that extract nested Intent objects from incoming Intent extras (e.g., via getParcelableExtra) and pass them directly to startActivity enable Intent Redirection attacks; search for getParcelableExtra followed by startActivity in exported activities.
2. Loading URLs directly from untrusted Intent extras into a WebView allows malicious apps to force arbitrary web pages to load; search for WebView.loadUrl() receiving parameters from getIntent() or getExtras() without validation.
3. Using loose suffix checks like endsWith() for host validation in deep links or URLs allows attackers to register domain names that bypass validation; look for URL host validation using endsWith() instead of strict URI host comparison.
4. Enabling setAllowUniversalAccessFromFileURLs(true) in WebView settings permits local file-based scripts to access cross-origin resources and private app files; search for setAllowUniversalAccessFromFileURLs(true).
5. Logging sensitive user information such as passwords, tokens, or credentials via system logging APIs exposes data to system logs; search for Log methods passing authentication parameters.
6. Sending implicit broadcasts containing sensitive payload data without specifying explicit target packages or requiring custom permissions permits any installed app to intercept data; search for sendBroadcast calls lacking target package definitions.
7. Exported Content Providers that return sensitive user data (such as credentials from SharedPreferences) in query() responses allow unauthorized third-party apps to access sensitive app data; inspect exported content providers and their query implementations.
8. Passing untrusted incoming intents back to caller components via setResult(RESULT_OK, getIntent()) enables intent reflection vulnerabilities; check for setResult calls utilizing raw getIntent() objects.
9. Storing hardcoded authentication credentials directly in application source code makes them susceptible to reverse engineering; search for static credential assignments and plaintext secret key mappings.

_Dropped by generality guard (instance-specific): 3_

## Ground-truth still missed after lessons

  - GT-03: Weak Host Validation Check (weak_host_validation)
  - GT-04: Arbitrary Code Execution (arbitrary_code_execution)
  - GT-06: Unprotected Data URIs (webview_untrusted_data_uri)
  - GT-07: Theft of Arbitrary Files (arbitrary_file_theft)
  - GT-08: Using Components with Known Vulnerabilities (known_vulnerable_component)
  - GT-10: AWS Cognito Misconfiguration (cloud_credential_misconfig)
  - GT-11: Insecure use of FilePaths in FileProvider (insecure_fileprovider)
  - GT-12: Use of Implicit intent to send a broadcast with sensitive data (implicit_intent_sensitive_data)
  - GT-13: Intercepting Implicit intent to load arbitrary URL (implicit_intent_url_interception)
  - GT-18: Insecure Data Storage (insecure_data_storage)
