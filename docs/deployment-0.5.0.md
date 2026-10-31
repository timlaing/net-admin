# Deploying 0.5.0

This is a deployment checklist for the prepared release. Local validation does not prove hosted CI, Home Assistant host policy, or behavior on your production network.

## Before publishing

Push the reviewed commits and require the CI and lint workflows to pass for the exact release commit. CI builds both amd64 and aarch64 images and runs container smoke tests, including real Bind dynamic updates and ISC/Kea subnet validation. The add-on metadata is version 0.5.0. Publish a GitHub Release tagged `v0.5.0` only after approval; a tag push alone does not publish images. Confirm the publication workflow succeeds and the versioned images exist before updating an installation.

## Before updating an installation

- Take a Home Assistant backup and separately preserve `/config/netadmin.env`, service configurations and includes, zone files and journals, DHCP leases, and PKI. Keep these backups private.
- Record the current application and agent image versions and the working connection settings.
- Check the existing Bind configuration with its native validator. DNS zone management currently rejects views and duplicate zone names.
- For managed zone creation, declare the selected TSIG key in Bind configuration. The agent selects `DNS_UPDATE_KEY`, then `NETADMIN_DNS_TSIG_NAME`, then `rndc-key`. Use the corresponding key for the web application's AXFR and dynamic updates.
- Keep service configuration writable only by the appropriate service/agent. Custom non-root Bind deployments need a writable zone directory and compatible host policy. The supplied DNS agent uses Alpine's Bind executable paths.

## Update and configure

1. Deploy matching agent versions before enabling new management controls. Keep mTLS and bearer authentication enabled. The web app does not write service configuration itself.
2. For DNS zone management, follow `docker-compose.dns-agent.yml` alongside the normal compose file. Provision the DNS agent server certificate for hostname `dns`, its client CA and the shared agent token. Configure the optional DNS agent URL as `https://dns:8083`. Existing direct Bind record management remains available without this agent.
3. Update and restart the Home Assistant add-on, or replace the standalone application container. Confirm login, current service inventory and connection diagnostics before changing configuration. Settings changes can reload the application configuration from the UI; replacing application code still requires restarting the container.
4. Keep `ingress_require_login` enabled initially. To delegate ingress administrator authentication, disable it only after verifying Supervisor 2026.10.5 or newer and your Home Assistant administrator account. Older or incomplete identity headers fall back to login. Direct access continues to require HTTPS login.
5. Test a non-production zone or subnet first. Confirm discovery, creation, edits and removal, plus the underlying service health. Removing a zone stops serving it but retains its files and journal; removing a subnet retains lease history.

The first DNS configuration mutation writes the canonical managed configuration and preserves the original main file as `.before-netadmin`. Existing includes remain on disk. DHCP changes preserve native ISC/Kea configuration and create an initial `.before-netadmin-subnets` backup; Kea subnet creation requires one `subnet4` array in the main configuration. These backups are an initial migration safety net, not a replacement for versioned backups.

Agent transactions constrain writes to configured service directories, including their subdirectories. DHCP permits the main configuration and managed-reservations directories; RADIUS permits its configured authorize and managed-user directories; DNS permits its main/managed configuration directories and configured zone directory. An include does not grant write access outside these directories, including through symlinks. Move external DHCP definitions into a permitted directory before editing them through NetAdmin.

## Rollback

Record any service changes made after the update before rolling back. Pin the application and agents to the previous known-good versions. If configuration restoration is needed, restore a consistent service backup, including referenced files and appropriate zone journals, and validate it with the native service tools before restarting. Do not blindly overwrite live zone data or lease databases with older copies. Restore the saved application settings when required, then verify service health, authenticated access, inventory and representative DNS/DHCP behavior.

The standalone container remains supported: use the standard application image, configure the documented environment variables and agents, and provide HTTPS through your reverse proxy. Home Assistant delegated ingress authentication applies only to the add-on.
