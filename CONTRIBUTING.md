# Contributing

Docker Who is an early attribution engine. Keep changes focused on connecting
local Docker request callers to host processes, and preserve explicit fallback
evidence when a user cannot be identified.

## Local development

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -e .
.venv/bin/python -m unittest discover -s tests -v
```

Use temporary fixtures for unit tests; never require access to real Docker
metadata or a production state file. For changes to the observer, describe the
Linux kernel, Docker, containerd, and bpftrace versions used for live validation.

## Bug reports and pull requests

Describe the command, expected attribution, observed evidence, and relevant
versions. Remove real usernames, container names, command lines, and private
host paths from shared logs and fixtures.

Include regression coverage for attribution changes. If a new Docker or kernel
layout is supported, document its prerequisites and failure behavior in the README.

Contributions are provided under the project's MIT license.
