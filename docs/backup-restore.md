# Backup and recovery

Run host operations outside the web app. Stop **every writer** for the selected
trees: service daemons, agents and CA runtime/issuers. This keeps SQLite journals,
Kea/ISC leases, zone journals and native issuer databases consistent. A live tar
copy is not an application-consistent backup. The tool requires explicit
`--quiesced` confirmation; it does not guess whether your installation is stopped.

Supply a separate 16–1024 byte recovery passphrase in a local 0600 file. Keep that
file separate from the encrypted archive and include it in your offline recovery
plan. Never put the passphrase in command arguments, release assets or logs.

The passphrase file must be a private regular file owned by the effective operator;
symlinks, FIFOs, foreign ownership and oversized files are rejected before reading.
New archives use format v2 with fixed scrypt parameters N=2^17, r=8, p=1 (about
128 MiB of KDF memory). Existing v1 archives remain readable with their original
parameters. Format versions are explicit; arbitrary KDF parameters are never accepted.

Install the operation boundaries separately in the operator environment before
running the CLI. Arguments must match these settings and cannot widen them:

```sh
export NETADMIN_OPERATIONS_ROOT=/srv/netadmin
export NETADMIN_BACKUP_DIRECTORY=/secure-backups
export NETADMIN_RESTORE_DIRECTORY=/srv
export NETADMIN_RECOVERY_PASSWORD_FILE=/secure/recovery-passphrase
```

Use dedicated trees, not filesystem `/`. Unrelated credential stores (`.ssh`,
`.aws`, `.gnupg`, `.kube`, `.docker`) and development trees are rejected. Select
mounted deployment state from the configured root; archives are confined to the
backup directory and restore targets are new children of the restore directory.

```sh
python -m netadmin.operations.backup create --root /srv/netadmin \
  --include config --include leases --include transport --include ca \
  --archive /secure-backups/netadmin.enc --password-file /secure/recovery-passphrase \
  --quiesced
python -m netadmin.operations.backup verify --archive /secure-backups/netadmin.enc \
  --password-file /secure/recovery-passphrase
python -m netadmin.operations.backup restore --archive /secure-backups/netadmin.enc \
  --password-file /secure/recovery-passphrase --target /srv/netadmin-restore-test
```

Selections are explicit relative paths: include all mounted configuration, leases,
transport PKI, environment assignments, management/provisioner credentials and CA
state/recovery material for **your** layout. Root paths above are examples, not a
baked-in deployment layout. Symlinks/special files are rejected; transient sockets
are omitted. Archive size is bounded to 256 MiB; partition larger installations
into consistent selections, or use native offline encrypted volume snapshots.

Restore only creates a NEW directory. It never overwrites live state. Test it on
an isolated host/network with the **same image versions** first, verify authority
fingerprints and representative DNS/DHCP/RADIUS/CA operations, then explicitly
switch mount paths while all services are stopped. Run restoration as root when
original issuer ownership must be preserved. Directory/file modes are preserved
without restoring setuid/setgid bits. Root directory is private by default.

Archives are written to an exclusive 0600 temporary file, then published without
overwriting only after the file is fsynced; the containing directory is fsynced too.
Selection limits apply during enumeration, not after traversing an unbounded tree.
Path lookup walks only selected parent directories, rejecting intermediate symlinks.

On restore failure, the tool cleans up only its newly created directory using
symlink-safe, descriptor-relative removal. Existing targets are never removed.
If permissions, filesystem errors, a replaced target or unsupported safe-removal
facilities prevent cleanup, partial private state may remain. Inspect the configured
restore storage and remove only the failed operation's partial directory after
checking its contents and identity; do not retry over it or remove a live deployment.
Likewise, inspect private backup storage for owned `.partial` files after a failed
cleanup. Trusted input failures have actionable messages; native/private diagnostics
remain suppressed. Never treat an unsuccessful operation as a verified backup.

Retain archives according to your recovery policy; rotate/test recovery passwords,
restrict backup storage, and keep an offline copy. CA authority deletion does not
invalidate external backups; secure their retention separately. Do not restore
old CA inventory automatically after issuing/revoking certificates on newer state.
