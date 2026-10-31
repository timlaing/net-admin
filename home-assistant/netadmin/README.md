# NetAdmin

Manage DNS, DHCP and RADIUS from Home Assistant through one web interface.

NetAdmin connects to Bind 9, ISC DHCPD or Kea, and FreeRADIUS. Manage DNS records,
DHCP reservations and RADIUS users while keeping each service as the source of
truth. DHCP and RADIUS changes go through restricted agents that validate the
configuration before applying it and roll back if reloading fails.

- Open the interface directly from Home Assistant using ingress.
- Create the emergency root account first, then enable and test connections in Settings.
- Use RADIUS accounts for everyday access, with separate administrator and standard roles.
- Let standard users change their own password without access to administration tools.

## Before you install

This add-on provides the NetAdmin web application. Bind, DHCP, FreeRADIUS and the
DHCP/RADIUS agents must be deployed separately and reachable from the add-on.
Agent connections require matching TLS certificates and a shared bearer token;
Bind requires zone-transfer and authenticated update permissions.

After installation, start NetAdmin and select **Open Web UI** to create the root
account. Restart, sign in, and open **Settings** to configure the services you use.
See the **Documentation** tab for connection requirements and troubleshooting.

[Project and deployment guide](https://github.com/timlaing/net-admin#readme) ·
[Report an issue](https://github.com/timlaing/net-admin/issues) ·
[MIT license](https://github.com/timlaing/net-admin/blob/main/LICENSE)
