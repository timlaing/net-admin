# Safe DHCP reservations

Select the subnet/VLAN and **Review reservation** before saving an address inside
a dynamic pool. The preview shows the original and proposed pool intervals. Check
the explicit pool-exclusion approval before saving. Both the reservation and pool
adjustment use one agent-owned validated transaction, with rollback on failure.

Review approval expires after 15 minutes and is invalidated by payload or native
configuration changes. No configuration snapshot is stored in the web database.
An active lease belonging to a different MAC must be resolved first; NetAdmin does
not delete leases or silently take an address from another device.

ISC permits distinct reservation names for the same MAC across different subnets.
Kea global reservations still require unique MACs. Pool-specific policies are
preserved when splitting pools; unsupported syntax requires native editing.
Removing a reservation does not automatically expand the dynamic pool again.

Preview, conflict checks and candidate generation use the same captured configuration
bytes signed by the approval token. The agent checks the entire safety read set
before installation, including unchanged include files. ISC allocation keywords
are matched case-insensitively; subnet-local includes are rejected rather than
guessing which pools they supply. Singleton pools can be removed by the editor.

Active-lease checks use the last declaration for each address. After applying the
configuration and reloading, the agent checks again: a newly conflicting lease
causes configuration rollback and a reload of the restored configuration. The
lease database is preserved; resolve the other device's lease before retrying.

All agent configuration writers share an exclusive `.netadmin-dhcp.lock` in the
main configuration directory. The lock is acquired before reading configuration
and held through candidate installation, validation, reload, lease verification
and rollback. It serializes separate workers and threads; do not delete or replace
the lock file while the agent is running. Preview requests use the same lock without
changing service configuration.

Native editors must cooperate with that same advisory lock, or operate only while
agent writers are stopped. Snapshot checks still detect many external edits, but
an advisory lock cannot serialize an editor that ignores it. Offline migration and
restore procedures must continue to stop all service/agent writers first.
