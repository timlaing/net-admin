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
