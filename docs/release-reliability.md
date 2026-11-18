# Publication reliability

The draft workflow takes its version/tag/title from add-on metadata on `main`.
It does not generate a new draft for an already-published version, and API errors
other than a confirmed 404 stop draft mutation. Bump the add-on version in a
reviewed PR before drafting the next release. Publishing the draft still creates
the tag; raw tag pushes do not publish images.

Image upload retries are bounded to three attempts and only recognized transient
missing-layer/network errors. Authentication and permission failures stop
immediately. Builds and smoke tests are not bypassed or repeated as "fixes".

Versioned manifests are published first. Anonymous checks cover service images
and both Home Assistant architecture images. Installer assets and the final
completion marker are uploaded only after those checks. `latest` promotion occurs
**after** readiness, not midway through unchecked image publication. OCI state
schema labels and the readiness marker carry the reviewed release policy.

`.github/release-policy.json` defaults image rollback to **false**. Mark it safe
only in a reviewed change with proven backward-compatible persistent-state
semantics. Schema changes must update the state schema; never promise rollback
across incompatible CA inventory or native service migrations.

The final workflow reports ready/failed status in a generated release-note section
without changing the tag, publishing another release or manually synthesizing
assets. Administrators can inspect `/releases/status` on demand; the app reports
**published-not-ready**, **publication-failed**, or **ready**, rather than treating
the existence of a GitHub release as successful delivery. Unknown/network failures
remain unknown. No registry credentials are sent to this readonly endpoint.

Publication is reported ready only when preparation, verification, lint, both
publishers, manifests, anonymous-access checks and installer publication all
succeed. Each gate is a direct dependency of the status job. Latest promotion
must also succeed for stable releases; only prereleases may skip it. Missing,
skipped, cancelled or failed mandatory jobs cannot produce a ready note.
