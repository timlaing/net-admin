# RADIUS authentication modes

Open **RADIUS → Authentication modes** to choose the methods allowed for devices:

| Mode | Credentials | Certificates |
| --- | --- | --- |
| EAP-MSCHAPv2 | Username and password; needs an NT hash | No TLS certificates |
| PEAP with MSCHAPv2 | Username and password inside TLS; needs an NT hash | Trusted server CA and server name configured on devices |
| EAP-TLS | Client certificate and private key | Server identity and trusted client CA |

Enable multiple modes during migration. The preferred mode is offered first;
a device can negotiate another enabled mode. Device profiles must be updated
separately. Saving restarts RADIUS and may interrupt authentication. PAP and
non-EAP authentication are unchanged.

The UI shows configured methods, not methods inferred from recent traffic.
Certificate navigation and details are hidden when the configuration confirms
that no enabled EAP method uses TLS. If an older or disconnected agent cannot
report this, certificate access stays available rather than guessing.

To prepare certificates before enabling PEAP or EAP-TLS, select that mode in the
form and use **Prepare certificates**. Expired or not-yet-valid certificates block
activation of TLS-based modes. Install CA trust and the expected server name on
devices; do not turn off server certificate validation. For PEAP, migrate cleartext
users to dual hashes, or reset crypt-only users' passwords to add NT hashes.

## Agent setup

Upgrade the web app and RADIUS agent together. Enable `RADIUS_AUTH_MANAGEMENT=true`
on the agent and configure the same acknowledged restart mechanism used by
certificate management (`RADIUS_CERT_RESTART_MODE` and
`RADIUS_CERT_RESTART_COMMAND`). A HUP-only reload does not reliably apply EAP module
changes, so authentication mode changes require a restart.

The agent must see the same complete native configuration as the service.
Mount `mods-available` and `sites-available` writable into the agent, and
`mods-enabled` and `sites-enabled` read-only to retain their native symlinks.
Share these directories with the service as shown in both Compose examples.
Mount directories rather than individual files so atomic replacement works.
For regular active files instead of symlinks, their containing directory must
also be writable. Override paths with `RADIUS_EAP_FILE` and
`RADIUS_INNER_TUNNEL_FILE` if necessary. Back up the native configuration first.

Standard FreeRADIUS 3 EAP and inner-tunnel configuration is supported. Included,
ambiguous or customized module calls are rejected for native editing. The UI
lists other EAP methods present in the source; saving replaces them with the
selected supported modes. Disabled method blocks remain commented in the file
so their custom settings can be restored on later toggles. The inner tunnel
uses a dedicated MSCHAPv2 EAP instance, allowing direct MSCHAPv2 to be disabled
without breaking PEAP. Tunneled replies retain user pool and address assignments.

The agent checks configuration revisions, validates using `radiusd -XC`, and
restores both files on validation or activation failure. Read-only agents reject
all writes. No privileged configuration writes occur in the web app.

## Safe upgrades and recovery

This credential format requires an exclusive writer. Stop **every old RADIUS
agent instance** before starting the upgraded agent or migrating/resetting users;
do not use a rolling deployment with mixed agent versions sharing these files.
Keep the old image stopped for rollback. Back up both `authorize` and `netadmin`
before the first paired-hash write. To downgrade, first restore that complete
pre-upgrade backup while agents are stopped. An old agent cannot safely edit the
new paired records; merely switching the image back is not a supported downgrade.

All user mutations are serialized across workers. Multi-file user and EAP
transactions persist a private `0600` rollback journal before replacing files.
On startup, an interrupted transaction is restored and the original service
configuration activated before requests are accepted. Keep the configuration
directories persistent, including their hidden journal files. A read-only agent
refuses pending recovery instead of modifying files. Do not remove a pending
journal to suppress a startup failure: restore write/restart access and let
recovery finish. Native editors should use the corresponding advisory lock;
changes observed before replacement reject the candidate rather than overwrite
an administrator's edits.

Migration hashes within a bounded ten-second batch budget (with five-second
limits per hashing subprocess) and the web request allows 80 seconds for hashing,
validation and reload. If a legacy file exceeds that budget, split it into smaller
batches before retrying; incomplete hashing never installs user changes.

Python callers needing a crypt string can continue using `hash_password`.
`hash_passwords` returns the paired credentials. Legacy string-returning migration
callbacks are accepted and preserve crypt-only records; use the paired callback
to add NT hashes during cleartext migration.
