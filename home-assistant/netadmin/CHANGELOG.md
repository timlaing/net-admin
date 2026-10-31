# Changelog

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
