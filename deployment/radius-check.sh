#!/bin/sh
# The normal image entrypoint prepares TLS, then calls this one-off override.
# Do not touch the live supervisor's shared restart acknowledgement files.
exec radiusd -C
