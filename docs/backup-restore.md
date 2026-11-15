# Backup and recovery

Run host operations outside the web app. Stop **every writer** for the selected
trees: service daemons, agents and CA runtime/issuers. This keeps SQLite journals,
Kea/ISC leases, zone journals and native issuer databases consistent. A live tar
copy is not an application-consistent backup. The tool requires explicit
`--quiesced` confirmation; it does not guess whether your installation is stopped.

Supply a separate 16–1024 byte recovery passphrase in a local 0600 file. Keep that
file separate from the encrypted archive and include it in your offline recovery
plan. Never put the passphrase in command arguments, release assets or logs.

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

Retain archives according to your recovery policy; rotate/test recovery passwords,
restrict backup storage, and keep an offline copy. CA authority deletion does not
invalidate external backups; secure their retention separately. Do not restore
old CA inventory automatically after issuing/revoking certificates on newer state.
