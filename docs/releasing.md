# Release checklist

1. Merge only after approval and passing checks for the exact release commit.
   Match the release tag to the add-on version. Publishing a GitHub Release starts
   image publication; pushing a tag does not.
2. When introducing a new GHCR package, its first image push creates it as
   **private**, even when the source repository is public. After that first push,
   open the package's **Package settings → Change visibility → Public** as its
   owner. For the first Kea release, do this for `netadmin-dhcp-kea` before making
   the installer available. This is package visibility, not Actions access or
   repository permission inheritance. See GitHub's
   [package visibility instructions](https://docs.github.com/en/packages/learn-github-packages/configuring-a-packages-access-control-and-visibility#configuring-visibility-of-packages-for-your-personal-account).
3. Confirm the release's multi-architecture manifests have been published. The
   **Verify anonymous image access** job inspects every release image, including
   Kea, with an empty Docker configuration and no registry login. If first-publish
   visibility prevents this job from passing, make the affected package public
   and rerun the failed job. The installer upload depends on this verification.
4. Confirm installer assets were uploaded only after anonymous access passed:
   `install.sh`, its SHA-256 checksum and `compose.yml`. The publication job uploads
   `installer-ready.json` last as its completion marker. The bootstrap ignores
   releases without the marker or with missing/incomplete installer assets, so a
   failed newer publication preserves the last verified installer. Never upload
   this marker manually to bypass the image or asset checks. A successful
   authenticated registry push alone is insufficient to release an anonymously
   usable installer.
5. Verify a fresh host can use the release-pinned installer without a GitHub or
   registry login. Check selected-service readiness before network traffic, then
   verify representative DNS, DHCP, RADIUS and CA operations for installed services.

6. On a fresh macOS host with Docker Desktop, install DNS, RADIUS and CA using a
   selected LAN address. From another LAN client, verify each agent's
   `/capabilities` endpoint on ports 8083, 8082 and 8084 over mTLS and bearer auth.
   Create a disposable managed CA in the UI and confirm its allocated listener
   in 9100–9115 is reachable from that client. Verify real DNS queries and RADIUS
   traffic too. The CI topology smoke rewrites ports to loopback; it does not
   establish LAN/firewall reachability, privileged port setup or first-run UI behavior.

To repeat the registry access check without publishing anything:

```sh
bash Tools/check_public_images.sh X.Y.Z
```

Replace `X.Y.Z` with the published release version. Package visibility can be
changed only after the package exists; this checklist does not authorize an
unreviewed release or publication of placeholder images.
