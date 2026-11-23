# APK Scan Run — 20261122-122343

- **Teacher:** `gemini:gemini-3.6-flash`
- **Student:** `gemini:gemini-3.1-flash-lite`
- **Match strategy:** `taxonomy`
- **Files scanned:** 25

## Recall (headline)

| Model | Recall | Findings |
|---|---|---|
| Teacher (reference ceiling) | 36.8% | 7 |
| Student — before lessons | 42.1% | 13 |
| Student — after lessons | 52.6% | 14 |

**Recall lift: +10.5% absolute (+25% relative)**

## General lessons used

1. Exported Android components that extract nested Intent extras and forward them to startActivity or startService introduce Intent Redirection vulnerabilities; search for getParcelableExtra calls whose output is passed directly to launch component methods.
2. Using naive string comparison methods like endsWith or contains for URL or hostname validation allows domain spoofing; search for string matching on domain parameters and verify that Uri.getHost() is used with exact host allowlists.
3. Instantiating classes from external applications using createPackageContext with CONTEXT_INCLUDE_CODE and CONTEXT_IGNORE_SECURITY enables arbitrary code execution; search for createPackageContext calls that use dynamic class loading or permissive context flags.
4. Logging sensitive user credentials, tokens, or personal identifiable information via system logging APIs exposes data to logcat; audit Log utility calls for references to sensitive variables.
5. Enabling setAllowUniversalAccessFromFileURLs or setAllowFileAccessFromFileURLs in WebSettings allows JavaScript executing inside file URLs to read arbitrary local files and bypass cross-origin restrictions; search WebSettings configurations for enabled file access flags.
6. Hardcoding cloud infrastructure configurations, AWS Identity Pool IDs, or API keys in application source code or XML resources allows unauthorized access via decompilation; search codebases and string resources for credential patterns.

_Dropped by generality guard (instance-specific): 1_

## Ground-truth still missed after lessons

  - GT-02: Insufficient URL Validation (webview_arbitrary_url_load)
  - GT-06: Unprotected Data URIs (webview_untrusted_data_uri)
  - GT-07: Theft of Arbitrary Files (arbitrary_file_theft)
  - GT-08: Using Components with Known Vulnerabilities (known_vulnerable_component)
  - GT-09: Insecure Broadcast Receiver (insecure_broadcast_receiver)
  - GT-10: AWS Cognito Misconfiguration (cloud_credential_misconfig)
  - GT-11: Insecure use of FilePaths in FileProvider (insecure_fileprovider)
  - GT-12: Use of Implicit intent to send a broadcast with sensitive data (implicit_intent_sensitive_data)
  - GT-13: Intercepting Implicit intent to load arbitrary URL (implicit_intent_url_interception)
