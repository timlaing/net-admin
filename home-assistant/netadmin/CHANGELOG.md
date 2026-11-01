# Changelog

## 0.7.0

- Require patched cryptography 50.x for certificate operations.

- Add RADIUS certificate inventory, public certificate/CRL downloads, CA and server renewal, server revocation with replacement, and explicit CA retirement/replacement. Certificate transactions validate and restart RADIUS with rollback on failure; private keys remain on the agent. Upgrade the RADIUS service and agent and mount their shared certificate volume before enabling management.

- Replace subnet edit links with buttons and add a structured pool and DHCP option editor, with individual Add/Remove controls, Undo and a review step before applying changes. Common options use friendly names; custom options and the text editor fallback remain available.

## 0.6.4

- Sort table columns in ascending or descending order, with keyboard controls, numeric ordering and sort indicators. Sorting works with search and pagination.

## 0.6.3

- Display agent access as a badge beside connection status on the overview, replacing the separate Access line.

- Default searchable tables to 10 rows per page. The 25, 50 and 100 row options remain available.

## 0.6.2

- Show agent access mode (Read-only, Writable or Unknown) alongside automatically refreshed connection status. Older agents without capability reporting remain Unknown.
- Hide write forms, action columns and mutation buttons on read-only DNS, DHCP and RADIUS service pages while retaining inventory and snapshot access.
- Replace inline subnet forms with a searchable, paginated table and dedicated subnet view/edit pages showing network identity, source, allocation pools and DHCP options.
- Validate pool boundaries, ordering and overlaps, reject malformed or duplicate options, and retain entered values after validation errors. Read-only subnet pages reject submitted edits.
- Preserve quoted ISC DHCP text options when reading and editing subnet configuration. Update the DHCP agent to 0.6.2 for this fix.

## 0.6.1

- Automatically show DNS/DHCP/RADIUS agent connection status on the overview, refresh every 30 seconds and keep live DNS transfer/RADIUS login diagnostics separate from agent connectivity.
- Support HTTP and HTTPS through verified Home Assistant ingress, including CSRF-protected forms, local login and first-run setup. Direct-access cookies remain Secure.
- Paginate searchable tables with 25 rows by default, selectable page sizes and independent controls for each table.
- Keep the DNS page available when live transfers fail, explain AXFR requirements and offer an explicit zone-file snapshot including its journal. Snapshots can lag Bind's in-memory state and do not change transfer policy.
- Show direct Bind settings immediately below the DNS section and expand them when disabling DNS agent mode.
- Add RADIUS client edit/delete controls and source labels. Update existing simple client blocks in place, preserve blank secrets and unrelated attributes, reject ambiguous/nested definitions, and roll back failed validation or reloads.
- Expose read-only agent capabilities with `NETADMIN_AGENT_READ_ONLY=true`; reject mutations server-side and disable their UI controls.
- Fix HTTPX client certificate loading when using a custom CA file, keeping certificate and hostname verification enabled.
- Upgrade DNS and RADIUS agents to 0.6.1 for zone snapshots, existing client management and read-only capability reporting. Existing agents remain compatible with their previous APIs; client editing requires the newer agent's source metadata.

## 0.6.0

- Add an exclusive Use DNS agent toggle: agent mode needs only the agent URL and shared agent security; direct mode uses Bind/TSIG settings. Inactive settings are preserved and ignored.
- Route DNS record reads, updates and deletes through the DNS agent, using its locally declared Bind key. Existing agent URLs select agent mode on upgrade unless explicitly overridden.
- Upgrade the DNS agent to 0.6.0 before the web app when using agent mode; older agents do not provide the record API.

## 0.5.1

- Consolidate DNS/DHCP/RADIUS connection settings in NetAdmin Settings. Import legacy Home Assistant option values without overwriting saved settings, then remove the retired options. Keep the ingress login policy in Home Assistant Configuration.
- Hide the HTTPS sign-in notice through trusted Home Assistant ingress, including when the internal forwarded connection uses HTTP.
- Keep HTTPS guidance for direct HTTP access, with wording appropriate to NetAdmin.

## 0.5.0

- Refreshed responsive interface with local assets, light/dark themes, search and useful empty states.
- Simplified connection settings, connection diagnostics and in-process configuration reload.
- Optional Home Assistant delegated administrator access through trusted ingress; direct access still requires login.
- Discover and manage multiple Bind zones through the optional authenticated DNS agent, including zone creation and removal.
- Discover ISC/Kea subnet definitions and manage subnets, pools and reservations in their native configuration files.
- Validate service configuration changes before installation and roll back when reload fails.
- Build and smoke-test the DNS agent on amd64 and aarch64; exercise subnet changes against real ISC and Kea parsers.

See `docs/deployment-0.5.0.md` in the repository for prerequisites, deployment and rollback preparation.
