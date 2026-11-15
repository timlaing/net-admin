# Coordinated, health-gated updates

`python -m netadmin.operations.update` is an **opt-in host operator**, not an agent
or web endpoint. It requires Docker access, an explicit plan and a separate private
backup passphrase file. Never mount the Docker socket into a service agent.

Example plan (adjust every path and service to your installation):

```json
{
  "root": "/srv/netadmin",
  "projects": [
    {
      "directory": "services",
      "file": "compose.yml",
      "project": "netadmin",
      "services": [
        "dns",
        "dhcp-isc",
        "radius",
        "dns-agent",
        "dhcp-agent-isc",
        "radius-agent"
      ]
    },
    {
      "directory": "ca",
      "file": "compose.yml",
      "project": "netadmin-ca",
      "services": ["ca-runtime", "ca-agent"]
    }
  ],
  "backup_directory": "/secure-backups/netadmin",
  "backup_includes": ["services", "ca"]
}
```

Use the explicit services in provider-first order within your Compose dependency
graph, and include **all** writers and mounted state. Unselected containers with
writable mounts inside the checkpoint root are refused. Host/native writers must
also be stopped by the operator; do not use this layout for unmanaged writers.
Every non-tmpfs service mount must be covered by the declared selection. Named
volumes outside the checkpoint root require a bind-mounted/exported backup layout
or native offline volume snapshots; they are refused rather than silently omitted.
Backup storage must be private and outside the source tree.

The coordinator requires a published stable release with all installer assets and
`installer-ready.json`. It verifies every image version/revision, requires image
health checks and pins immutable repository digests. It stops the whole cohort,
captures an encrypted checkpoint, rehearses restoration, and starts providers then
dependents using Compose health gates. It never removes volumes, changes tags or
prints credentials/service startup output. Repeated runs are idempotent.

Pause WUD/external automatic updates before the **first** `--adopt` invocation.
The managed override disables Docker/Compose updating triggers, including explicit
per-instance overrides, while retaining WUD watching/notifications. Include
`netadmin-release.override.json` in manual Compose invocations afterward. WUD no
longer independently replaces one member of the cohort; the host timer performs
release-aware automatic updates. Do not enable a second automatic update owner.

Install the example `deployment/netadmin-update.service` and `.timer` only after
editing paths, testing the plan and verifying notification/log monitoring. This
implementation does **not** modify your live WUD configuration or install a timer.

Failures before activation resume prior services. Failures after activation stop
the cohort and retain both encrypted checkpoints and private restored rehearsals.
Treat rehearsals as secret-bearing backups (0700 storage). **No automatic data
rewind occurs.** Image-only rollback additionally requires `--allow-image-rollback`
and an explicit publisher `image_rollback_safe: true` declaration. Do not use it
unless the publisher state schema also matches every prior image. Interrupted
operations leave private checkpoint journals with immutable previous image refs;
pending journals block later updates until the operator verifies recovery and
marks the journal phase `recovered`. Do not clear this gate without checking state.
after incompatible migrations or external issuance/revocation. Recover state
manually with the version-matched procedure in [backup-restore.md](backup-restore.md).
