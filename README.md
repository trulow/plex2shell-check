# Plex2Shell Security Checker

A read only Bash checker for selected Plex Media Server compromise indicators on **Linux**, including Plex running in **Docker**. It reports the installed Plex version, compares it with the minimum version that addresses the 2026 Plex2Shell vulnerabilities, and checks whether Plex reports a newer public release.

> **A PASS is not a guarantee of safety.** This tool searches for a limited set of known indicators at the time it runs. A compromised host can evade these checks, logs may be missing, and previously removed evidence cannot be detected by this script.

## Project origin and attribution

Adapted from [gmolveau's original Plex2Shell check Gist](https://gist.github.com/gmolveau/b02c2e58b877cf138e2859dbfb5cc20e). This repository contains independent changes and is **not affiliated with, endorsed by, or maintained by Plex or the original author**.

**Licensing:** No explicit license was identified in the original Gist during this review. Attribution does not grant permission to redistribute copyrighted code. Please clarify permissions with the original author before redistributing this derivative or adding a license purporting to cover their work.

## What changed, and why

| Improvement | Reason |
| --- | --- |
| Query the Plex `/identity` endpoint | Docker installations may set `VERSION=docker`, which is an image setting rather than the installed Plex version. The original numerical comparison failed on `10#docker`. |
| Parse the `MediaContainer` version | The XML declaration also contains `version="1.0"`; the script must extract the actual server version instead. |
| Validate and compare numeric versions | Reject nonnumeric version strings rather than allowing arithmetic errors or a false PASS. |
| Inspect Docker networking through `nsenter` and host `ss` | Minimal container images may not contain `ss`; the host tools can inspect the container's network namespace without installing anything inside it. |
| Separate codec inspection from temporary file inspection | Normal Plex codecs are `.so` libraries. Flagging every codec library creates misleading warnings. |
| Report missing required checks | An unavailable log, network tool, or running version must not quietly turn into a complete clean scan. |
| Add the official Plex release lookup | Meeting the fixed Plex2Shell patch threshold is different from running the latest published Plex release. An available update is a warning, **not** evidence of compromise. |
| Avoid printing matched log lines | Logs may contain authentication tokens and other private data. |
| Preserve the original human readable summary | Keep `[PASS]`, `[WARN]`, `[FAIL]`, `[SKIP]` output and clear exit codes. |

## Requirements

- Linux with Bash and common command line utilities (`grep`, `sed`, `find`, `ps`).
- Permission to inspect local Plex and, for Docker installs, access to the Docker daemon. Running with `sudo` is recommended when appropriate.
- Docker CLI for container installations.
- `curl` for checking Plex's running version and the Plex release feed. The Docker identity check uses `curl` inside the container, or `wget` as a fallback. A restricted host identity fallback is used only for one Plex container with no native Plex installation.
- Host `nsenter` and `ss` for Docker network inspection, or `ss` inside the Plex container as fallback.
- `jq` **or** Python 3 to parse the official Plex downloads JSON.
- Outbound HTTPS access to `plex.tv` for the optional update status check performed by the script.

The script does not install dependencies, restart containers, upgrade Plex, remove files, or intentionally change configuration. It **does** make local HTTP requests and an outbound HTTPS request to Plex's download API; normal logging or network side effects may occur.

## Quick start

Review the script before executing it with elevated privileges:

```bash
curl -fsSL https://raw.githubusercontent.com/trulow/plex2shell-check/main/plex-check.sh -o plex-check.sh
bash -n plex-check.sh
sudo bash plex-check.sh
```

For a Plex Pass release channel comparison:

```bash
sudo env PLEX_RELEASE_CHANNEL=plexpass bash plex-check.sh
```

To disable colored output:

```bash
sudo env NO_COLOR=1 bash plex-check.sh
```

The release lookup targets `https://plex.tv/api/downloads/5.json` and normally reads the **Linux public** release version. This is not necessarily the version available for every NAS package or Docker image. A failed release lookup creates a warning but does not invalidate completed local checks.

## Checks the script actually performs

| Check | Method and limits |
| --- | --- |
| Install discovery | Finds running Docker containers with `plex` in their name or image; also checks standard `dpkg`, `rpm` and systemd native installations. Stopped or unusually named containers may be missed. |
| Running version | Queries `/identity` inside the container, with a limited host fallback; native installs use package information or host `/identity`. Invalid versions are UNKNOWN. |
| Plex2Shell patch level | Compares the version to `1.43.3.10861`, which Plex identified as not affected by the four reported Plex2Shell issues. This **does not** identify future vulnerabilities. |
| Latest Plex release | Fetches Plex's Linux version field from its downloads API using `jq` or Python. An update is reported as WARN. |
| Processes | Searches `docker top` or native `ps` output for selected miner/proxy names and patterns. Renamed malware may be missed. |
| Temporary files | Checks files under `/tmp` and `/var/tmp` to a maximum depth of two directories for selected names or `.sh` and `.so` extensions. Matches trigger WARN, not automatic malware confirmation. |
| Plex Codecs | Searches Plex Codecs directories for `.so` and `.sh` files, then flags filenames containing `xmrig`, `myawesomeproxy`, `/tmp/`, or ending in `.sh`. **Arbitrary malicious `.so` files may go undetected.** |
| Network | Uses `nsenter` and `ss` (or container `ss`) to inspect currently established connections for the selected ports `3333`, `14444`, `14433`, and `45700`. The pattern matches these ports on either side of a connection and does not prove mining activity. Other ports and past connections are not inspected. |
| Logs | Checks the last 72 hours of Docker logs plus the accessible current Plex application log for selected exploit request patterns. Missing, rotated, or alternate logs may omit evidence. |
| Native persistence | For native installs only, checks recently modified SSH `authorized_keys` files and selected cron entries. This is not a comprehensive persistence audit. |

## Understanding the results

| Output | Meaning |
| --- | --- |
| `[PASS]` | That specific check ran and did not find its selected indicator, or met the fixed version threshold. |
| `[WARN]` | Review a possible suspicious finding or an available Plex update. Warnings do not necessarily mean a compromise. |
| `[FAIL]` | A selected compromise indicator or a Plex version below the configured security threshold was detected. Investigate. |
| `[SKIP]` | A check could not run or data was inaccessible. |
| `RESULT: INCOMPLETE` | At least one required local check could not establish a result. |

Exit codes:

| Code | Meaning |
| --- | --- |
| `0` | All required local checks ran without a selected FAIL; **warnings can still be present**. |
| `1` | Selected indicator detected or configured security minimum failed. |
| `2` | No supported Plex installation detected. |
| `3` | Required checks were incomplete or the running Plex version was unknown. |

**Important:** WARN findings for temporary files or codec scripts do not currently make the exit code nonzero. Monitoring and automated workflows should not interpret exit code `0` as “no issues to review.”

## Illustrative output

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

This is an example from a previously reported run, **not a live statement about the latest release**.

## Validation

```bash
bash -n plex-check.sh
bash tests/validate.sh
```

The included test only checks Bash syntax and the presence of certain functions. It does **not** execute the entire scanner with simulated failure cases and does not prove its security detections are complete. Test on the Linux environments you intend to support.

## Security response

If a check reports a possible compromise, preserve relevant logs and evidence, restrict exposure, investigate any unknown processes or connections, and follow Plex's official incident response guidance. Avoid deleting evidence or a Plex data directory solely because a name matched a broad pattern. Update Plex from a trusted source and review account tokens and credentials if compromise is suspected.

## References

- [Plex security announcement and Plex2Shell details](https://forums.plex.tv/t/important-security-update-for-plex-media-server-v1-43-2-and-earlier/942319/)
- [Official Plex Media Server downloads](https://www.plex.tv/media-server-downloads/)
- [Plex downloads API](https://plex.tv/api/downloads/5.json)
- [Original gmolveau Gist](https://gist.github.com/gmolveau/b02c2e58b877cf138e2859dbfb5cc20e)
