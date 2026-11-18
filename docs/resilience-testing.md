# Failure-path testing

The normal Python 3.12-3.14 CI and multi-architecture service smoke suites remain
the release gates. The additional PR/main/nightly resilience workflow tests staged
descriptor cleanup, native-edit snapshot rejection, interrupted journal blocking,
unknown-schema rollback refusal, restore-rehearsal failure and missing health gates.

Its real Docker smoke uses disposable stub services with **no network** and a
unique Compose project. A new image writes synthetic state and deliberately fails
health. The test requires the cohort to stop, an encrypted checkpoint to remain,
and the new state NOT to be silently rewound. It never pushes registry images,
uses real CA keys, mounts the host socket into agents or accesses production state.

Run `sudo .venv/bin/python Tools/smoke_update_failure.py` on an isolated Linux Docker
host. macOS native unit tests still run locally; the real Engine smoke runs on
Linux CI to avoid Docker Desktop host/VM bind-path translation ambiguity.
Temporary decrypted rehearsals and containers are destroyed with the isolated
fixture. Do not adapt this smoke to live service paths or production projects.
