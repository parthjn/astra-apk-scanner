# APK Scan Run — 20261122-122524

- **Teacher:** `gemini:gemini-3.6-flash`
- **Student:** `gemini:gemini-3.1-flash-lite`
- **Match strategy:** `taxonomy`
- **Files scanned:** 25

## Recall (headline)

| Model | Recall | Findings |
|---|---|---|
| Teacher (reference ceiling) | 0.0% | 0 |
| Student — before lessons | 42.1% | 13 |
| Student — after lessons | 42.1% | 13 |

**Recall lift: +0.0% absolute (+0% relative)**

## General lessons used

_(none)_

## Ground-truth still missed after lessons

  - GT-03: Weak Host Validation Check (weak_host_validation)
  - GT-05: Access to Protected Components (intent_redirection)
  - GT-06: Unprotected Data URIs (webview_untrusted_data_uri)
  - GT-07: Theft of Arbitrary Files (arbitrary_file_theft)
  - GT-08: Using Components with Known Vulnerabilities (known_vulnerable_component)
  - GT-09: Insecure Broadcast Receiver (insecure_broadcast_receiver)
  - GT-10: AWS Cognito Misconfiguration (cloud_credential_misconfig)
  - GT-11: Insecure use of FilePaths in FileProvider (insecure_fileprovider)
  - GT-12: Use of Implicit intent to send a broadcast with sensitive data (implicit_intent_sensitive_data)
  - GT-13: Intercepting Implicit intent to load arbitrary URL (implicit_intent_url_interception)
  - GT-18: Insecure Data Storage (insecure_data_storage)
