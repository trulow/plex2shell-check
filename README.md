# Plex Media Server compromise checker

A read only Bash script for checking selected **Plex2Shell** compromise indicators on Linux, including Plex installed in Docker containers. It keeps the original `[PASS]`, `[WARN]`, `[FAIL]`, `[SKIP]` and summary display.

> **Important:** A clean indicator scan is not proof that a Plex server has never been compromised. The minimum version check covers the 2026 Plex2Shell issue, not every possible future Plex vulnerability.

## Original project and attribution

This project is adapted from **gmolveau's** GitHub Gist, [“Check if plex installation is hacked #plex2shell”](https://gist.github.com/gmolveau/b02c2e58b877cf138e2859dbfb5cc20e), first published October 19, 2026. The original checker, original project description and original author should retain attribution in any redistribution. This project is an independently modified version; it is not an official Plex security tool and is not presented as a release by the original author.

The original Gist does not provide a clear license notice in the reviewed material. **Do not assume the original code has an open source license.** Confirm redistribution permission or licensing with the original author before publicly publishing this derivative. The original Gist can be forked through the Gist interface while maintaining provenance, subject to GitHub's terms.

## Requirements

* Linux and Bash (run with `bash plex-check.sh` or execute the script directly).
* Docker CLI access when Plex is running in Docker; `sudo` is recommended.
* `curl` for version discovery and official release lookup. An identity request is sent to the local Plex `/identity` endpoint.
* `ss` and `nsenter` on the Docker host for network inspection. If absent, the script tries `ss` inside the container.
* `jq` **or** Python 3 to parse Plex's official release API JSON.
* Standard GNU commands such as `find`, `grep`, `sed`, and `ps` for applicable checks.

The script does not install dependencies, stop containers, modify Plex settings, or delete files. The latest release lookup requires an outbound HTTPS request to `plex.tv` and therefore is not a fully offline scan. Running the script still generates routine logs and network traffic as the underlying tools normally do.

## Usage

```bash
chmod +x plex-check.sh
sudo ./plex-check.sh
```

Run against Plex Pass release channel instead of public releases:

```bash
sudo PLEX_RELEASE_CHANNEL=plexpass ./plex-check.sh
```

To disable ANSI color codes:

```bash
sudo NO_COLOR=1 ./plex-check.sh
```

The script discovers containers whose name or image includes `plex` and also checks standard Linux package/service installs. It does not automatically detect every custom layout, NAS operating system or non Linux installation.

## Checks performed

| Check | What it inspects |
| --- | --- |
| Local Plex version | Reads the running Plex `/identity` endpoint inside the Docker container, with a restricted host fallback for a single Plex container; uses package information or the endpoint for native Plex |
| Plex2Shell minimum | Compares the running version against `1.43.3.10861`, the minimum configured in the original script |
| Official release | Queries Plex's HTTPS downloads API (`https://plex.tv/api/downloads/5.json`) to check the latest public Linux release; Plex Pass channel is optional |
| Processes | Looks for selected miner and proxy process patterns |
| Temporary files | Searches known temporary directories for selected suspicious names and extensions |
| Plex Codecs | Ignores ordinary codec library names, while flagging selected suspicious names including `zz<hex>.so` and scripts |
| Container network | Uses host `nsenter` and `ss` to inspect the **container's network namespace**, avoiding the need to install `ss` inside minimal container images |
| Logs | Checks available recent Docker logs and Plex application logs for selected exploit request patterns |
| Native persistence | Checks selected SSH `authorized_keys` changes and cron entries when a native install is detected |

The script does **not** perform exhaustive malware detection, forensic image analysis, historical network analysis, or comprehensive current vulnerability tracking.

## Why the original script was changed

1. **Correct Docker version detection.** Some Plex Docker images set `VERSION=docker`. This is not the Plex Media Server version and caused the original version comparison to fail with `10#docker` while misleadingly printing a final PASS. The updated checker queries the real running server and rejects nonnumeric version strings.
2. **Correct XML parsing.** Plex's `/identity` XML has an XML declaration with `version="1.0"` and a `MediaContainer` attribute containing the real Plex version. The parser explicitly targets the latter.
3. **Inspect Docker networking automatically.** Minimal containers often lack `ss`. The checker can use the host's `nsenter` and `ss` inside the container's network namespace.
4. **Treat incomplete checks honestly.** An inaccessible log, missing tool, invalid version, or other skipped required check is no longer silently converted into a clean scan.
5. **Reduce harmless codec alerts.** Standard Plex codecs are not considered compromise evidence merely because they are `.so` files. Selected abnormal names remain subject to review.
6. **Separate security and currency.** Meeting the fixed Plex2Shell version threshold and being on the latest official Plex release are two different questions. Available updates produce a warning, not an assertion of compromise.
7. **Avoid displaying sensitive log content.** Matching log lines are not printed, because Plex logs can contain authentication material.
8. **Retain readable output.** The original human readable `[PASS]`, `[WARN]`, `[FAIL]`, `[SKIP]` format and final summary remain.

## Example output

```text
Detected install(s): docker plex

--- Checking: docker plex ---
[PASS]  Plex version 1.43.5.11029-6bf8af3f0 meets Plex2Shell security minimum (1.43.3.10861)
[PASS]  No miner/proxy process patterns in container plex
[PASS]  No suspicious files in /tmp or /var/tmp of container plex
[PASS]  No selected suspicious file patterns in Plex Codecs folder (plex)
[PASS]  No connections to selected mining ports (container plex)
[PASS]  No selected exploit signatures in container Docker logs (plex, last 72h)
[PASS]  No selected exploit signatures in Plex application log (plex)

--- Checking: latest official Plex release (public) ---
Official Plex release version: 1.43.5.11079-b3b13e506
[WARN]  Plex update available: installed 1.43.5.11029-6bf8af3f0; latest public 1.43.5.11079-b3b13e506

============================== summary ==============================
Indicators: 0 | Warnings: 1 | Skipped: 0
RESULT: PASS with 1 warning(s) to review manually.
```

*Example based on a previously observed run, not a live statement about the latest Plex version.*

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | No selected compromise indicators found and required local checks completed. Update warnings and other warnings may still be present. |
| `1` | A configured version threshold failed or a selected compromise indicator was detected. |
| `2` | No supported Plex installation was detected. |
| `3` | Required checks could not be completed, so a clean result cannot be established. |

`WARN` findings other than an outdated release may require manual investigation even if the exit code is zero. Network connections can be transient, logs can rotate, and process and file names can change.

## Security and privacy

* Review scripts before executing them as root.
* No automatic repairs, container restarts, configuration changes, downloads or deletions take place.
* The official release lookup contacts `plex.tv`. For full offline use, remove or skip that lookup in a locally reviewed copy.
* The local Plex identity endpoint may include a machine identifier in its response; the script extracts the version only.
* Detected indicators merit investigation, not immediate deletion of evidence.
* Keep Plex up to date, limit remote access where possible, and rotate tokens if compromise is suspected.

## Validation

Syntax check:

```bash
bash -n plex-check.sh
```

The source is intended for Linux and Docker. Tests on mocked Plex services cannot replace testing on real supported Plex deployments.

## Sources

* [Original gmolveau Gist](https://gist.github.com/gmolveau/b02c2e58b877cf138e2859dbfb5cc20e)
* [Plex official downloads](https://www.plex.tv/media-server-downloads/)
* [Plex downloads API used by script](https://plex.tv/api/downloads/5.json)
