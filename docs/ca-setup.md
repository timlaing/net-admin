# Create a root and issuing CAs in NetAdmin

This workflow uses the standalone **CA runtime + CA agent** deployment in
`docker-compose.ca.yml`. The existing `docker-compose.step-ca.yml` integration
remains available for authorities initialized outside NetAdmin.

## Deployment and connection

The CA runtime generates and encrypts its root private key on its first boot into
an empty persistent volume. It then waits for you to create the root certificate
in NetAdmin. Restarting or replacing the container reuses that key. Missing or
inconsistent state is an error; the runtime never silently replaces an existing
root. Existing step-ca directories require an explicit migration and are rejected
as bootstrap storage.

The deployment uses an independent agent transport CA, mTLS client/server
certificates and the existing bearer token. These must already exist, as they do
for an existing NetAdmin agent deployment. They are separate from the root you
create in the wizard. The optional installer accepts them without sourcing shell
configuration or copying other service secrets:

```sh
bash scripts/install-ca.sh \
  --directory /srv/netadmin-ca \
  --pki-dir /srv/netadmin-agent-server-pki \
  --agent-env /srv/netadmin-agents/agents.env \
  --version VERSION \
  --bind 192.0.2.10 \
  --dry-run
```

Replace `VERSION` with an explicit release containing `netadmin-ca-runtime` and
replace the example paths/address. Remove `--dry-run` to install. The server
certificate must cover the address/hostname the Home Assistant app will use.
Choose a private interface reachable by the app; the script does not alter the
firewall, device trust or existing service containers. It rejects an existing
conflicting Compose project. Re-running against its own installation reports the
existing deployment and leaves state intact. Upgrades use that project's Compose
file explicitly; they do not reinitialize the CA. A rerun validates configuration only;
it does not check startup or resume an interrupted pull/start. Run that project's
`pull` and `up -d --no-build` commands to resume. Installer bearer tokens cannot
contain apostrophes; use the manual Compose deployment below for such tokens.

The runtime image is a new release artifact. Until a release publishes it, build
this branch locally for evaluation:

```sh
docker build -f docker/Dockerfile.ca-runtime -t ghcr.io/timlaing/netadmin-ca-runtime:local .
docker build -f docker/Dockerfile.ca-agent -t ghcr.io/timlaing/netadmin-ca-agent:local .
# Set NETADMIN_VERSION=local in the deployment .env, then use up --no-build.
# Skip pull for these local-only images until a release publishes them.
```

For manual Compose deployment, prepare `transport/server.crt`, `server.key` and
`ca.crt`, a restricted `runtime.env` containing `NETADMIN_AGENT_TOKEN`, and a
restricted `secrets/management-token` containing a separate random secret of at
least 32 characters. Copy the standalone Compose example into that deployment
directory, set `NETADMIN_VERSION` and `CA_BIND_ADDRESS` in its `.env`, validate it,
then use `docker compose ... pull` and `up -d --no-build`. Keep both signing state
and secret files out of Git. The example defaults to loopback publication.

In Home Assistant's NetAdmin app, open **Settings → CA**:

- **CA agent HTTPS URL**: `https://192.0.2.10:8084` in this example.
- **CA lifecycle management token**: the secret in `secrets/management-token`.
- **Agent security**: existing bearer token, trusted transport CA, and matching
  client certificate/key paths in the app's filesystem.

Save, then open **Certificates**. Changes apply without an app restart. Standalone
web deployments use `NETADMIN_CA_AGENT_URL` and `NETADMIN_CA_MANAGEMENT_TOKEN`
alongside the existing agent transport environment variables.

The installer deliberately uses existing transport trust. Automatic fresh-host
pairing is a separate future workflow, not an unauthenticated initialization API.

## Create the root certificate

The Authorities page shows the fingerprint of the already-generated root public
key. Enter CN, optional organization/unit/country/state/locality, optional DNS/IP
SANs and lifetime in days. One year is 365 days. The default root lifetime is 7300
days; the supported maximum is 36500 days. Keys use ECDSA P-384.

Set **Further CA levels allowed below this CA** to 1 for a root → issuing-CA
hierarchy, or 2 if you also need an intermediate delegation layer. A value of 0
prevents subordinate creation. This becomes the certificate's immutable
`pathLenConstraint`; it is not merely a UI preference.

CA certificate SANs do not restrict issuance. The service's HTTPS DNS/IP addresses
and its permitted issuance names are separate fields on an issuing CA.

Confirm and choose **Create root certificate**. The public certificate/chain can
then be downloaded. The runtime signs using its existing root key; it will not
create another root over the same state. A separate root deployment is required
for a new trust hierarchy in this version.

## Create subordinate CAs

Choose a parent and provide the child's CN/subject, optional SANs, lifetime and
further CA levels. The child's complete validity must fit its parent, and its
path-length limit must be smaller. A default issuing CA has path length 0.

For a **managed issuing CA**, also enter:

- The service hostname or IPv4 address clients will use.
- Permitted DNS domains and/or IP networks, supplied as comma-separated values.
  Each domain allows itself and its direct subdomains; add deeper zones explicitly.
  Omitted name types are denied by the managed issuer policy.
- Maximum leaf-certificate lifetime in days (default 365; maximum 3650).

The controller creates a separate key, database, provisioner credential and native
step-ca process for each managed issuer. Up to 16 managed issuers use the fixed
published port pool 9100–9115. The assigned HTTPS endpoint appears on its card.
This explicit port pool avoids exposing container-management privileges to the UI.
Internal HTTPS names `localhost` and `ca-runtime` are included automatically.
Runtime issuance policies on children must narrow their ancestors' permitted names,
networks and leaf lifetimes. They are distinct from certificate NameConstraints.

For an **external subordinate**, expand the CSR section and paste its signed CA
CSR. Its public key is used with the subject and CA limits you specify; arbitrary
CSR extensions are not copied. The external system retains its private key, and
NetAdmin does not start an issuing process for it. Download the signed chain for
installation there. If signing below a parent with an issuance policy, supply
compatible child scope. Explicit external scope becomes critical certificate
NameConstraints. Root-level external subordinates may be unconstrained when you
leave scope fields empty.

The ordinary leaf CSR API still rejects CA requests. Subordinate signing requires
both administrator access and the separate lifecycle management credential.

## Issue, revoke and renew certificates

Use **Issue a leaf certificate** on the selected managed issuer's card. Submit a
CSR and lifetime; keys remain with the requester. Download the signed chain.
**Issued certificates & revocation** lists certificates issued through that runtime
and offers revocation by hexadecimal serial and an authoritative CRL download.
The public CRL URL is embedded in issued leaf certificates.

Native Smallstep clients can renew against the issuer endpoint using their
existing key/certificate. This UI does not install a renewal client on the target
machine. Direct renewals are not included in the runtime's issuance list; revoke
using the current serial. Clients must fetch/enforce the published CRL to reject
an unexpired revoked certificate.

Creating an issuer does not enrol FreeRADIUS or change Wi-Fi/VPN trust. Existing
RADIUS enrolment/renewal integration remains a separately configured workflow.
Intermediate revocation and root trust rotation require their own planned
migration; this interface does not offer an ambiguous delete/recreate button.

## Root recovery and archival

After creating the root, choose an independent recovery passphrase of at least
16 characters and download the encrypted JSON recovery file. Store its passphrase
separately. That file contains the encrypted root key and public certificate; it
contains no decryption password. Responses are not cacheable, and secrets are not
recorded in audit entries or SQLite.

To archive the online root, upload that saved recovery file and enter its
passphrase. The controller verifies the decrypted key matches the root, then
requires `ARCHIVE ROOT` confirmation before removing the online key and its
bootstrap wrapping secret. Existing issuing CAs continue serving. The durable root
manifest prevents restart from treating archival as an empty installation.

To sign another subordinate later, supply the encrypted recovery file and
passphrase in that operation's recovery section. Decryption/signing occurs in the
CA runtime; the plaintext root key is not saved or returned to the web app/agent.
This temporarily makes root signing available online. Fully offline signing via
CSR export/import is not included in this version.

The recovery file is not a complete online-issuer backup. Preserve CA state,
issuer databases/configuration/keys, management credentials and revocation records
with consistent backups, and test restoration separately. Never restore a stale
issuer database that loses issuance or revocation history.

## Interrupted operations and rollback

Each form carries a stable operation ID. On an interrupted request, use **Check
operation** and inspect Authorities before submitting another operation. A changed
payload cannot reuse an existing ID. Completed retries return the recorded result;
uncertain attempts are retained for reconciliation and are not automatically
signed again. Validation rejections display a bounded message without echoing
private material.

To disconnect, clear the CA agent URL in Settings and stop only this
Compose project. Retain its volumes and secrets. Existing independent NetAdmin
service containers and certificate backends are not changed.

Managed issuers run as separate numeric users (20000–20015). The controller
retains only CHOWN, SETUID, SETGID and KILL capabilities to prepare read-only native
inputs, drop privileges and stop expired or shutting-down child processes. Each issuer has its own writable runtime directory,
no supplementary groups and a minimal environment without lifecycle credentials.
Root keys, wrapping secrets, controller metadata and sibling issuer keys remain
inaccessible to issuer users. Native logs rotate at one MiB with one backup;
failed issuer restarts back off from five seconds to five minutes.

The installer checks that the runtime responds and the agent is listening, and
that its TLS files parse. This is not an authenticated TLS chain or hostname
check. NetAdmin validates those when connecting with its configured trust and
client certificate; use that connection test before treating the agent as ready.

The CA runtime indexes only public issued certificates in a private local SQLite
inventory. No private keys, passwords or service configuration enter this index.
Existing public leaf PEMs are imported once per issuer; subsequent pages use an
indexed cursor and parse at most 50 certificates.
