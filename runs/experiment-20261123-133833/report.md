# Ablation experiment — 20261123-133833

- App ground truth: `./data/ground_truth/insecurebankv2.yaml`
- Teacher: `gemini-3.6-flash`  Student: `gemini:gemini-3.1-flash-lite`
- Match: `taxonomy`  Repeats/arm: **3**
- Lessons source: `loaded:experiment.json`

## Recall by arm (mean ± sd over repeats)

| Arm | Mean recall | Std dev | Min | Max | Δ vs baseline | Samples |
|---|---|---|---|---|---|---|
| baseline | 66.7% | 0.0% | 67% | 67% | — | 67%, 67%, 67% |
| control | 75.0% | 0.0% | 75% | 75% | +8.3% | 75%, 75%, 75% |
| lessons | 75.0% | 0.0% | 75% | 75% | +8.3% | 75%, 75%, 75% |

## Distilled lessons (accepted)

1. Dynamic code loading via createPackageContext with CONTEXT_INCLUDE_CODE combined with reflection allows arbitrary code execution from external or spoofed packages; search for createPackageContext paired with getClassLoader().loadClass().
2. Exported components that extract a nested Intent from incoming extras and pass it directly to startActivity or startService enable intent redirection vulnerabilities; search for getParcelableExtra calls whose results are forwarded to component launch methods.
3. Validating domains using partial string matching methods like endsWith allows domain spoofing attacks (e.g., attacker domain appending the legitimate name); use strict Uri parsing with Uri.getHost() and explicit domain checks instead.
4. Enabling setAllowUniversalAccessFromFileURLs(true) or setAllowFileAccessFromFileURLs(true) on WebSettings allows local file schemes to bypass cross-origin policies and read local application files; inspect all WebSettings configurations for file access flags.
5. Overriding onReceivedSslError in a custom WebViewClient to call handler.proceed() disables SSL certificate validation and exposes network traffic to Man-in-the-Middle (MitM) attacks; search for SslErrorHandler.proceed() usage.
6. Broadcasting sensitive data using implicit Intents allows any application installed on the device to register a receiver and steal secrets; use explicit Intents with setPackage() or restricted permissions for sensitive broadcasts.
7. Exported Content Providers that expose database or SharedPreferences data via query() allow any third-party application on the device to read sensitive information; audit provider declarations in the manifest and ensure exported components enforce proper read/write permissions.
8. Reflecting an incoming Intent directly back to the caller via setResult(RESULT_OK, getIntent()) can leak sensitive extras or intent data to arbitrary launching activities; sanitize intent extras before passing them to setResult.
9. Storing authentication credentials or sensitive data in standard unencrypted SharedPreferences exposes them to theft via backup or root access; store sensitive data using EncryptedSharedPreferences backed by the Android Keystore.
10. Embedding hardcoded credentials, cloud identity pool IDs, or API keys directly in source code or string resources exposes infrastructure and services to unauthorized access; search source code and XML resources for hardcoded secret strings.
11. Setting android:debuggable="true" in AndroidManifest.xml permits attackers to attach a debugger to the process, inspect runtime memory, and execute arbitrary code; ensure debug mode is disabled in production builds.
12. Setting android:usesCleartextTraffic="true" allows the application to send unencrypted HTTP network traffic, exposing sensitive data to interception; enforce TLS by configuring Network Security Config and disabling cleartext traffic.
13. Setting android:allowBackup="true" without restriction allows physical or ADB access to extract application private storage via adb backup; set allowBackup to false or restrict sensitive paths using fullBackupContent.

## Control checklist (generic, used in the `control` arm)

1. Review every exported component (activity, service, receiver, provider) and confirm it enforces an appropriate permission.
2. Validate and sanitize all data received from Intents, extras, and deep links before use.
3. Ensure sensitive data (credentials, tokens, PII) is encrypted at rest and never written to logs.
4. Verify TLS certificate and hostname validation is never disabled or bypassed.
5. Check WebView configuration for unsafe settings such as JavaScript, file access, or universal access from file URLs.
6. Audit ContentProviders and FileProviders for over-broad access and missing access control.
7. Look for hardcoded secrets, credentials, API keys, or cloud configuration in code and resources.
8. Ensure broadcasts and intents carrying sensitive data are explicit and permission-protected, not implicit.
