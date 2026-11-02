# Service logs

Administrators can open **Service logs** to view four separate pages: RADIUS
Login Log, DHCP Lease Log, DDNS Change Log, and RADIUS Sessions. They use the
existing search and 10/25/50/100-row pagination controls. On small screens tables
scroll horizontally. Use Refresh to fetch the latest retained records.

These pages do not insert records into Activity or the overview's Recent Activity.
Activity continues to show NetAdmin sign-ins and administrative operations.

## Agent configuration

Upgrade the web app and the corresponding agent. Configure these environment
variables **on the agent**, using absolute container paths:

| Agent | Variable | Source |
| --- | --- | --- |
| RADIUS | `RADIUS_AUTH_LOG_FILE` | FreeRADIUS `radius.log` |
| RADIUS | `RADIUS_ACCOUNTING_DIR` | FreeRADIUS `radacct` directory |
| DHCP | `DHCP_LOG_FILE` | Dedicated ISC dhcpd or Kea DHCP4 log file |
| DNS | `DNS_UPDATE_LOG_FILE` | Dedicated BIND `update` category log file |

Mount existing service log directories read-only into their matching agents.
For example, an operator-managed RADIUS log directory can be mounted as
`/srv/radius-logs:/logs/radius:ro`, with `RADIUS_AUTH_LOG_FILE=/logs/radius/radius.log`
and `RADIUS_ACCOUNTING_DIR=/logs/radius/radacct`. Give the agent OS user read
permission. Prefer directory mounts so daemon log rotation remains visible.
No Docker socket, daemon restart command, or write access is needed for these endpoints.
Existing agents in read-only mode support the GET endpoints.

Unconfigured, missing or unreadable sources display an unavailable message.
A reachable source with no recognized records displays an empty state.
Older agents returning 404 display an upgrade/configuration message. Direct Bind
connections cannot supply DDNS logs; configure a DNS agent for that page.
The default Compose stacks do not collect these files automatically. Their
stdout-only logs must first be routed to dedicated files by your logging setup;
pointing an agent at a lease database does not provide a lease event history.
Do not mount all host logs or enable password/debug logging for this feature.

## Supported native records

* FreeRADIUS 3 `Login OK` / `Login incorrect` messages with `from client` fields.
  Enable authentication result logging (`auth = yes`) while keeping
  `auth_goodpass = no` and `auth_badpass = no`. Responses contain only timestamp,
  username, client, calling station and outcome. Password suffixes and rejection
  diagnostics are discarded.
* ISC `DHCPACK`, `DHCPRELEASE`, `DHCPNAK` and Kea `DHCP4_LEASE_ALLOC` /
  `DHCP4_LEASE_REUSE` messages. ACKs may represent allocation or renewal; the UI
  retains the daemon event name rather than claiming every ACK is a renewal.
* BIND `update` messages containing `updating zone` and an RR add/delete or rrset
  delete. Enable a dedicated file channel for the `update` category. These are
  record mutation messages, not rejected update requests. BIND generally does not
  include deleted RR values, so the page shows the value only when recorded;
  it cannot reconstruct previous values or guarantee final transaction commit.
  One DDNS transaction may produce several rows, including forward/reverse zones.
* FreeRADIUS native accounting detail files at `radacct/<NAS>/detail-*` with
  `Timestamp`, `Acct-Session-Id` (or `Acct-Unique-Session-Id`), NAS address and
  `Acct-Status-Type`. Auth detail files are never read. Enable the `detail` module
  in accounting, and configure access points/switches to send Start, Stop and
  interim updates (for example every five minutes).

Sessions are keyed by NAS and session ID. Start resets reused IDs; interim and
Stop records update them. Reported duration, timestamps, MAC/IP, NAS, called
station and input/output counters are shown where available, including 32-bit
counter wraps. Active means a Start/interim record was received within 15 minutes;
a missing Stop eventually becomes Stale, not a confirmed disconnect. NAS
Accounting-On/Off messages mark existing unfinished sessions stale. This is an
accounting view, not a real-time device inventory. Without interim updates even a
connected device becomes stale. Records without a NAS/session identifier are ignored.

## Retention and limits

No service logs or service configuration are stored in NetAdmin's SQLite database.
The source daemon/log collector owns retention. Each file read is capped at its
last 2 MiB and each page at 500 rows. Event pages read the current file only.
Accounting traverses at most 256 NAS directories and 4096 entries per directory.
It reads at most 256 detail files and 16 MiB per request, newest files
first; archive older detail files when the file count exceeds this limit.
Rotated compressed logs are unsupported. Only complete accounting blocks ending
with a blank line are consumed. History outside the retained window cannot be
reconstructed; session fields can be incomplete. The page always identifies this
as a bounded recent view. Source log timestamps retain their daemon timezone;
accounting timestamps are displayed in UTC. Malformed/unrecognized lines are ignored.

Reference: [FreeRADIUS logging](https://wiki.freeradius.org/config/Logging),
[FreeRADIUS accounting](https://wiki.freeradius.org/guide/Data-Usage-Reporting),
and [BIND logging categories](https://bind9.readthedocs.io/en/latest/reference.html).
