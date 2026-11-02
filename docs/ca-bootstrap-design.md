# CA initialization and hierarchy interface

Status: design and future extensions. The implemented first release is documented
in [Create a root and issuing CAs](ca-setup.md): it uses ECDSA P-384, one root per
deployment, existing mTLS transport trust, and a fixed 16-issuer port pool instead
of the proposed dynamic router. Fresh pairing, algorithm selection, additional
roots in one deployment and fully offline CSR signing are future extensions.
Existing certificate operations remain documented in
[Certificate management](certificates.md).

## Intended experience

Deploy the CA runtime and registration agent, connect them in NetAdmin, then
complete certificate-authority setup in the interface. The CA container generates
the root private key at its first initialization. The administrator subsequently
chooses the root certificate's subject and lifetime, and creates subordinate CAs
for issuance. No manual editing of CA configuration or key generation is required.

An optional installation script prepares container deployment and transport
authentication. Authority names, lifetimes, policies and subordinate creation
belong to the interface and use the same backend regardless of installation method.

## First container start: generate the root key

The CA runtime starts in a waiting state when its persistent volume is empty.
Before accepting initialization requests, its controller:

1. Takes an exclusive initialization lock and checks the durable state manifest.
2. Generates a root private key inside the CA container. Default: ECDSA P-384;
   a documented first-boot deployment option may select RSA 4096 instead.
3. Encrypts and atomically persists the key in a controller-only root vault,
   with a separately permissioned bootstrap wrapping secret. Both must persist
   across container replacement until root recovery material is exported.
4. Records the root public key, public-key fingerprint, algorithm and creation
   time. Marks the state `key_ready` only after durable writes finish.
5. Exposes setup status through the authenticated registration agent. The issuing
   service remains stopped until a usable issuing CA has been configured.

The web app and registration agent never receive the unencrypted key or its
bootstrap wrapping secret. The public-key fingerprint shown before creation is
distinct from the certificate fingerprint shown after the root is signed.

Subsequent starts reuse the recorded key. They never generate a replacement just
because a file is missing or cannot be decrypted. Inconsistent state becomes
`recovery_required`. After deliberate removal of online root material, the public
manifest remains, so restart cannot mistake an archived root for a fresh install.

Root algorithm is displayed read-only in the wizard because the key already
exists. Changing it requires an explicit discard-and-regenerate action, available
only before any root certificate or subordinate has been created. Subject, DNS/IP
SANs and lifetime remain configurable in the UI before root certificate creation.

## Navigation and first-run screens

Keep **Certificates** visible for administrators even when no CA agent URL has
been saved. Its empty state offers **Connect CA containers** and deployment help.
Add the CA connection to Settings; currently `ca_agent_url` is environment-backed
but absent from the editable connection sections.

Use tabs within Certificates: **Authorities**, **Issued certificates**,
**Revocation**, and **Connections & backups**. Preserve existing certificate URLs.
On mobile, show authority cards with a parent breadcrumb; on desktop, show an
expandable hierarchy beside the selected authority. Forms use visible labels,
field errors, keyboard navigation and a single column on narrow screens.

The initial flow is:

1. **Connect**: agent HTTPS address, existing agent credentials or a pairing flow;
   verify transport trust and show runtime/agent versions and storage readiness.
2. **Create root certificate**: configure subject, SANs and lifetime using the
   already-generated key. Preview the complete certificate before confirmation.
3. **Create issuing CA**: configure an initial subordinate, or finish with the
   root ready and create subordinates later. Recommend keeping root signing
   separate from routine leaf issuance.
4. **Recovery material**: download encrypted root recovery material, record its
   fingerprint and confirm safe storage. Explain the consequences before removing
   the online root copy; a successful download alone does not prove a backup.
5. **Ready**: show authority status, expiry, public chain downloads and a test
   issuance action. RADIUS enrolment remains a separate explicit operation.

## Root and subordinate forms

| Field | Root CA | Subordinate CA |
| --- | --- | --- |
| Display name | Required UI label | Required UI label |
| Parent | Self-signed root | Select a CA allowed to sign this child |
| Common name (CN) | Required; proposed default `Network Root CA` | Required; e.g. `Network Issuing CA` |
| Organization, unit, country, state, locality | Optional subject fields | Optional subject fields |
| Certificate DNS/IP SANs | Optional, under advanced subject fields | Optional, under advanced subject fields |
| Certificate lifetime | Editable; proposed default 20 years | Editable; proposed default 5 years |
| Exact validity dates | Show computed UTC start/end; advanced explicit dates | Same, constrained by parent validity |
| Key algorithm | Existing generated root key, read-only | ECDSA P-256/P-384 or RSA 3072/4096 |
| Allow further subordinate CAs | Sets path-length limit; default allows issuing children only | Off by default (`pathLenConstraint=0`) |
| Issuance policy | Optional constraints on descendants | Permitted DNS suffixes, IP ranges and certificate purposes |
| Leaf lifetime policy | Inherited defaults for children | Minimum/default/maximum; proposed default 24h, maximum 365 days |

Lifetime entry accepts days or years, displays the exact expiry, and defines one
year as 365 days. The parent must cover the child's complete validity period;
show an error and the maximum permitted end date rather than silently truncating.
Use a small fixed not-before clock-skew allowance and display it in the preview.
The key algorithm, lifetime, naming and extension limits must be enforced by the
backend as well as form validation. CN remains within the existing 64-byte limit.

Keep three different concepts visibly separate:

- **CA identity**: CN, subject and optional SANs on the CA certificate.
- **Service addresses**: DNS names/IPs clients use to reach the issuing HTTPS
  service. These belong on its separate TLS server certificate, not implicitly on
  the CA certificate. Include internal container DNS and any external endpoint.
- **Permitted issuance names**: DNS/IP policy for certificates the CA may issue.
  A SAN on the CA certificate does not constrain its descendants.

Simple root → issuing-CA hierarchies are the default. Advanced users may create
an additional intermediate layer if the entire chain's path-length constraints
permit it. Increasing a limit on an already-signed certificate requires issuing
a new certificate; changing UI metadata cannot modify the existing certificate.
If certificate NameConstraints are used, descendant constraints must remain
compatible with all ancestors. Runtime policies must also be enforced at every
applicable issuance boundary; the UI must not imply provisioner policy alone is
an X.509 constraint enforced by relying clients.

## Authorities screen and lifecycle

Example hierarchy:

```text
Certificates / Authorities                 [Create root CA] [Create subordinate CA]

Network Root CA                   Root · recovery material archived
├── Network Server Issuing CA     Active · expires 2031-11-02
└── Network Device Issuing CA     Active · expires 2031-11-02

Selected: Network Server Issuing CA
Subject | Parent | Validity | Fingerprint | Policy | Health
[Issue certificate] [Download certificate] [Download chain] [Create subordinate]
```

Each authority has a stable ID, parent ID, immutable certificate identity and
separate editable policy revisions. Show disabled, awaiting-signature, active,
expiring, expired, revoked and unavailable states explicitly. New roots can coexist
with older roots for a trust migration; creating one never overwrites another.
There is no ambiguous **Recreate CA** button. Downloading an existing public root
certificate, reissuing an intermediate, and creating a new trust root are distinct
operations with their own impact previews.

**Create subordinate CA** supports two modes:

- **Managed issuer**: generate its key in the CA runtime, create a CA CSR, obtain
  the parent's signature and start a managed issuing service with its own
  configuration, database, provisioner credentials and revocation state.
- **External issuer**: inspect an uploaded CA CSR and return its signed
  certificate/chain. Its private key and issuing service remain on the external
  system. This does not create a managed issuing process.

Signing from an archived/offline root offers **Unlock root for this operation**
using encrypted recovery material and its passphrase, or **Download CSR / Import
signed CA certificate** for signing elsewhere. Unlocking is limited to the selected
operation, is not persisted in browser/session state, and clears temporary material
after completion or failure. Browser → web app → agent uploads are size-bounded
streams to the CA controller; no plaintext key is written into web or agent storage.
The UI states that this mode temporarily makes root signing available online.

CA signing uses a dedicated administrator-only lifecycle endpoint and fixed CA
templates (`CA:TRUE`, certificate/CRL signing usage and validated path length).
Lifecycle mutations require a separate management credential held by NetAdmin,
not the shared leaf-issuance credential available to RADIUS. Enforce that scope in
the agent/controller as well as administrator authentication and CSRF in the web
app. Read-only deployment mode disables lifecycle mutations too.
The existing leaf CSR endpoint continues rejecting CA requests. An external CA CSR
must not choose its own effective authority privileges through arbitrary extensions.

Issuance requires an explicit issuer selection when multiple issuers exist. An
optional default preserves the current single-issuer API contract. Record issuer
ID on all operations and filter inventory/CRLs by issuer. Inactive or expired
parents block new signatures as appropriate; descendant validity is checked along
the complete chain. Revocation of an intermediate shows affected descendants and
requires publishing the parent's CRL, including an offline signing workflow when
the parent is offline. Disabling issuance is not described as revocation.

## Runtime architecture and persistence

Preserve the boundary: Flask web app → authenticated registration agent → CA-local
controller. Only the CA runtime controller manages authority keys, configuration
and child processes. No Docker socket, host PID namespace or web-app service-file
writes are required.

Introduce a NetAdmin CA runtime image containing a controller and pinned Smallstep
tools. The controller supervises one step-ca process per managed issuer, with
separate storage and loopback listeners. A runtime HTTPS router exposes stable
issuer-specific paths for signing, renewal and CRLs; internal port allocation never
requires editing host Docker mappings from the UI. Verify path routing, advertised
URLs and CLI compatibility with the pinned step-ca version before adopting this
router design. Root authorities remain offline signing identities, not default
public signing services.

The registration agent uses a private Unix control socket, with authenticated
peer access and an allowlist of lifecycle operations, sizes and fields. It cannot
submit arbitrary commands, paths, environment variables or templates. It receives
public results and encrypted exports, never a signing-key mount. Transport PKI
remains independent of every root managed by the UI, so creating a new authority
does not break management access.

Store controller metadata/configuration in versioned, permission-restricted files
beside the appropriate authority state. Keep keys in separate restricted stores;
SQLite remains limited to existing sessions, audit and rate-limit uses. Use a
controller-owned staging directory, atomic publication and a durable operation
journal. Each mutation has an idempotency key, payload digest, expected revision
and status endpoint. After timeout, poll that operation; never generate another
key or root as an automatic retry. Concurrency, partial initialization, failed
activation and missing-volume cases must have deterministic recovery states.

Backups distinguish encrypted root recovery material from online issuer database,
keys, configuration, credentials, inventory and revocation records. Use a separate
user-supplied recovery passphrase to re-encrypt root material before export; never
include its decryption secret in the same archive. Root archival removes both the
online encrypted root key and the now-unused bootstrap wrapping secret only after
explicit confirmation. Existing issuer state must remain backed up independently.
Responses carrying secrets or recovery material use no-store headers and never
enter logs, audit payloads, HTML previews or cookies.

## Installation script decision

Provide an optional, idempotent `scripts/install-ca.sh` alongside a standalone
Compose example. Both support a remote Home Assistant web app and an existing
NetAdmin deployment without deploying DNS/DHCP/RADIUS again. The script is an
installation convenience; manual Compose deployment must reach the same wizard.

The installer should:

1. Offer a dry run and check Docker/Compose versions, architecture, free ports,
   persistent directory ownership and existing deployment manifests.
2. Fetch published, version/digest-pinned images; generate only container/transport
   configuration and scoped credentials. Root key generation stays in the CA
   container, including for script installations.
3. Prefer existing independent agent transport trust where available. For a fresh
   installation, produce a short-lived, high-entropy pairing code and transport
   certificate fingerprint. Display the secret once to the operator, never in
   Docker command arguments or normal logs.
4. Start only the CA runtime and registration agent with `--no-build`, fixed
   permissions, dropped capabilities and persistent volumes. Handle the step-ca
   executable's file capabilities in the runtime image build; do not grant host
   privileges. Disable the Gunicorn control socket on read-only agent filesystems.
5. Print the endpoint, fingerprint and next UI action, then exit after readiness
   checks confirm `key_ready`. It must not initialize certificate subjects, replace
   existing keys, change host trust/firewall policy or enrol RADIUS automatically.

Fresh pairing requires an explicit new bootstrap protocol, not the current agent
API: verify the displayed transport fingerprint before sending the pairing secret;
accept only a client CSR with the one-time code over pinned HTTPS, rate-limit and
expire it, then close pairing after consumption. Every management operation remains
mTLS plus bearer authenticated. Generate the client private key in NetAdmin and
persist it only in its protected connection files. Per-CA transport overrides are
additive, falling back to existing shared credentials so other agents keep working.
Require a host-side action to reopen expired pairing; do not expose remote reset.

Rerunning the installer validates and reports existing state. Upgrades preserve
state and require an explicit version choice. Provide rollback instructions and
keep a manifest of installer-owned resources. Never delete a CA volume on failure.

## Implementation order and acceptance

1. CA runtime controller, first-boot key generation and durable state machine;
   validate restart and recovery behavior before adding creation screens.
2. Settings connection/pairing, root certificate wizard and encrypted recovery flow.
3. Managed/external subordinate creation, hierarchy, issuer selection and isolated
   issuance/renewal/CRL routing. Include more than one issuer in the first release
   claiming hierarchy support.
4. Optional installer, standalone Compose documentation and upgrade/rollback guide.

Acceptance includes blank-volume boot, exactly-once root-key generation under
concurrent starts, selected subjects/SANs/lifetimes, expiry/path/policy violations,
two independent issuers, offline root signing, external CSR signing, unauthorized
requests, read-only mode, CSRF/admin controls, interrupted operations, backup restore
and rejected replay. Verify leaf requests still reject CA privileges. Test the real
container startup and restart paths, actual pinned step-ca issuance/renewal and CRL
behavior, plus phone/tablet/desktop form layout and keyboard accessibility.

The existing live installation must be discovered/imported without generating a
new root or replacing its trust. Missing keys must be reported as offline or needing
recovery. An upgrade must not interpret pre-existing step-ca state as an empty volume.

## Upstream references

The design wraps existing Smallstep primitives; its controller and UI are proposed
NetAdmin additions. Confirm algorithms, templates, validity and path constraints
against pinned binaries during implementation.

- [Certificate creation: root/intermediate profiles, templates and validity](https://smallstep.com/docs/step-cli/reference/certificate/create/)
- [CA initialization and importing existing root/intermediate material](https://smallstep.com/docs/step-cli/reference/ca/init/)
- [CA configuration: signing keys, provisioners, policy and issuer settings](https://smallstep.com/docs/step-ca/configuration/)
