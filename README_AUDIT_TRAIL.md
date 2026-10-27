# CxOne Audit Trail Export

## Summary

`audit_trail.py` reads audit events from a Checkmarx One (CxOne) tenant for a given time range, filters them, and writes the matching events to a JSON file. It can optionally add each acting user's email and name. The JSON can then be ingested by downstream tools if desired. 

Each run is logged in detail under `logs/`.

## Usage

```
python audit_trail.py -c <config.ini> [options]
```

Use `pip install -r requirements.txt` to ensure all dependencies are available. A placeholder config file is provided, which can be edited for your tenant.

```ini
[CXONE]
ast_host = https://<YOUR_AST_HOST>
iam_host = https://<YOUR_IAM_HOST>
tenant = <YOUR_TENANT_NAME>
api_key = <YOUR_API_KEY>
```

### Parameters

| Parameter | Default | Description |
|---|---|---|
| `-c`, `--config` | required | Config file. |
| `-d`, `--days` | `7` | Look back this many days. Ignored when `--from` is given. |
| `-f`, `--from` | `--days` ago | Start of the range (date or timestamp). |
| `-t`, `--to` | end of today | End of the range, inclusive (date or timestamp). |
| `--action` | all | Keep events with this `actionType` (exact, ignores case). |
| `--resource` | all | Keep events with this `auditResource` (exact, ignores case). |
| `--change-type` | all | Comma separated `data.changeType` values, for example `"state,severity"`. Matches any of them (trimmed, exact, ignores case). Events without a `changeType` are excluded. |
| `-u`, `--user` | all | Keep events whose `actionUserId` contains this text. |
| `--ip` | all | Keep events whose `ipAddress` contains this text. |
| `-s`, `--search` | none | Keep events containing this text anywhere (ignores case). |
| `--user-lookup` | off | Add `actionUser` (email), `actionUserFirstName` and `actionUserLastName` after `actionUserId`. |
| `--out` | current folder | Output folder (existing, or ending in `/`) or file path. |
| `--log-dir` | `./logs` | Folder for the log file. |
| `--tenant-id` | from config | Use another tenant than the one in the config. |
| `--workers` | `4` | Time windows fetched at the same time. |
| `--window-hours` | `24` | Size of each time window, in hours. |
| `--page-size` | `1000` | Events per API call (max 1000). |
| `-v`, `--verbose` | off | Print one line per window. |
| `--insecure` | off | Skip TLS certificate verification. |

The API filters only by time, so all other filters run on your machine. A narrow filter does not make a run faster; a narrow time range does.

Output file: `audit_<from>_<to>.json`, sorted oldest first. If nothing matches, no file is written.

### Timestamps

- `--from` / `--to` take a date (`2026-10-05`) or a timestamp (`2026-09-14T15:42:37.881290Z`). Seconds and fractions are optional.
- A timestamp ending in `Z` or an offset (`-05:00`) is used exactly as given.
- A date or timestamp with no `Z` or offset is read as the **local time of the machine running the script**. A date means the whole local day.
- `--to` is inclusive. Output `eventDate` values are always UTC.
- Use `Z` or offsets for scheduled jobs and shared commands, so the range is the same on every machine.

### Windows and workers

The script has been written to optimize for large date ranges. It splits your range into **windows** and fetches several of them at once with **workers**.

- **Window** (`--window-hours`, default `24`): one slice of the time range.
- **Worker** (`--workers`, default `4`): how many windows are fetched at the same time. 

The output is identical whatever values you use. The defaults will work for most tenants. Tune them only if a run is slow or if you see too many 429 errors in the logs.

| Situation | Try |
|---|---|
| Short range (a day or two) | Nothing. There are only a few windows, so extra workers sit idle. |
| Long range (weeks or months) | Raise `--workers` (for example `8`), a step at a time. |
| Busy tenant: a single day takes a long time | Make windows smaller, `--window-hours 4` or `1`. A day then becomes 6 or 24 windows that can run in parallel. |
| Errors saying a window holds too many events | Make windows smaller. |
| The API answers `429` (too many requests) or `5xx` | Lower `--workers` (even to `1`), and try `--page-size 100`. May not be a bad idea to engage and work with Checkmarx PS. |


```bash
# defaults: 7 windows of 24 hours, 4 at a time
python audit_trail.py -c config.ini --days 7

# busy tenant: 42 windows of 4 hours, 8 at a time
python audit_trail.py -c config.ini --days 7 --window-hours 4 --workers 8

# a rate-limited API: one window at a time, smaller pages
python audit_trail.py -c config.ini --days 7 --workers 1 --page-size 100
```

## Examples

### Time range

```bash
# last 7 days (default)
python audit_trail.py -c config.ini

# last 30 days
python audit_trail.py -c config.ini --days 30

# one local day
python audit_trail.py -c config.ini --from 2026-10-05 --to 2026-10-05

# a date range
python audit_trail.py -c config.ini --from 2026-10-01 --to 2026-10-15

# from a date until now
python audit_trail.py -c config.ini --from 2026-10-01

# local time, 9 AM to 5 PM on the machine's clock
python audit_trail.py -c config.ini --from 2026-09-14T09:00 --to 2026-09-14T17:00

# exact span in UTC
python audit_trail.py -c config.ini --from 2026-09-14T15:42:37.881290Z --to 2026-09-14T18:00:00Z

# US Eastern Standard Time (UTC-5), 9 AM to 5 PM
python audit_trail.py -c config.ini --from 2026-01-15T09:00:00-05:00 --to 2026-01-15T17:00:00-05:00

# US Eastern daylight time (UTC-4), 9 AM to 5 PM
python audit_trail.py -c config.ini --from 2026-09-14T09:00:00-04:00 --to 2026-09-14T17:00:00-04:00

# a whole UTC day, the same on every machine
python audit_trail.py -c config.ini --from 2026-10-05T00:00:00Z --to 2026-10-05T23:59:59.999999Z

# one exact moment
python audit_trail.py -c config.ini --from 2026-09-16T02:47:19.330846Z --to 2026-09-16T02:47:19.330846Z
```

### Filters

```bash
# only updates
python audit_trail.py -c config.ini --action update

# only role events
python audit_trail.py -c config.ini --resource role

# role updates
python audit_trail.py -c config.ini --resource role --action update

# role deletes in the last 30 days
python audit_trail.py -c config.ini --resource role --action delete --days 30

# result state changes
python audit_trail.py -c config.ini --change-type state

# state or severity changes
python audit_trail.py -c config.ini --change-type "state,severity"

# spaces are ignored
python audit_trail.py -c config.ini --change-type " state , severity , status "

# severity changes made to results, in a date range
python audit_trail.py -c config.ini --from 2026-10-01 --to 2026-10-15 --change-type severity

# everything one user did (by user id)
python audit_trail.py -c config.ini --user dfc31dc7-4665-4021-a5c2-723207b9f22b

# everything from one IP address
python audit_trail.py -c config.ini --ip 198.51.100.77

# everything from an IP range (partial match)
python audit_trail.py -c config.ini --ip 198.51.100.

# events mentioning a name anywhere, including inside the data
python audit_trail.py -c config.ini --search "Global-Admin"

# several filters together (all must match)
python audit_trail.py -c config.ini --resource role --action update --ip 198.51.100.77 --days 14
```

### User details

```bash
# add the acting user's email and name to each event
python audit_trail.py -c config.ini --user-lookup

# role updates with user details
python audit_trail.py -c config.ini --resource role --action update --user-lookup

# state changes with user details for a date range
python audit_trail.py -c config.ini --change-type state --from 2026-10-01 --to 2026-10-15 --user-lookup
```

### Output and logs

```bash
# write into a folder (created if needed)
python audit_trail.py -c config.ini --out reports/

# write to a specific file
python audit_trail.py -c config.ini --out reports/role-updates.json

# keep logs somewhere else
python audit_trail.py -c config.ini --log-dir /var/log/cxone_audit

# folder for output and logs, e.g. for a Splunk forwarder
python audit_trail.py -c config.ini --out /var/log/cxone_audit/ --log-dir /var/log/cxone_audit/logs
```

### Large ranges and tuning

```bash
# a year, in 1-day windows, 8 at a time
python audit_trail.py -c config.ini --days 365 --workers 8

# a busy tenant: small windows, more parallelism
python audit_trail.py -c config.ini --from 2026-10-01 --to 2026-10-07 --window-hours 4 --workers 8

# the API answers 429 or 5xx: go gentler
python audit_trail.py -c config.ini --workers 1 --page-size 100

# see progress, one line per window
python audit_trail.py -c config.ini --days 90 --verbose
```

### Other

```bash
# another tenant than the one in the config
python audit_trail.py -c config.ini --tenant-id other-tenant

# corporate proxy with a private certificate (use with care)
python audit_trail.py -c config.ini --insecure
```

### Sample output

Default (events exactly as the API returns them):

```json
[
  {
    "eventID": "72e73776-bd2b-43b4-959f-1065ce6718a1",
    "eventDate": "2026-09-16T02:47:19.330846Z",
    "eventType": "role.update",
    "auditResource": "role",
    "actionType": "update",
    "actionUserId": "dfc31dc7-4665-4021-a5c2-723207b9f22b",
    "ipAddress": "198.51.100.77",
    "tenantID": "3d0b65d9-da24-4331-8528-2f3a32fcef49",
    "data": { "name": "AuditTest", "roleId": "aa7bc8bc-5f0a-4e30-91e2-f53f7572d3b6" }
  }
]
```

With `--user-lookup`, three fields are added after `actionUserId` (null if the user cannot be found):

```json
    "actionUserId": "dfc31dc7-4665-4021-a5c2-723207b9f22b",
    "actionUser": "r.vance@example.com",
    "actionUserFirstName": "Reese",
    "actionUserLastName": "Vance",
```
