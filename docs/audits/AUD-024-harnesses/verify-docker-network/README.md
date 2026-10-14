# Network setting of the canonical Dockerfile's RUN steps

Audit AUD-024, at commit b6fca69238344dd2525b06270ee6ff3b055e68c1.

`docker_network_steps.py` reads `packaging/Dockerfile.reproducible` and
`scripts/build-reproducible.sh` from git at the commit it is given, joins continuation lines and
prints every RUN step with its stage and whether it carries `--network=none`. It then lists each
RUN after the comment line "No network from here on" that lacks `--network=none`, and says whether
the build script passes a network option to `docker buildx build`.

Inputs: the git repository only. No Docker, build, network or Argon2.

Command, from the repository root:

```sh
python3 docs/audits/AUD-024-harnesses/verify-docker-network/docker_network_steps.py b6fca69238344dd2525b06270ee6ff3b055e68c1
```

Expected output at b6fca69: RUN 21 (argon2-wasm) and RUN 126-130 (verified) with "network:
default", only RUN 102-119 with `--network=none`, the line
"AFTER CLAIM, NOT --network=none: lines 126-130 (stage verified)", "build-reproducible.sh passes
--network to docker: False", and exit 1. A fixed Dockerfile (every RUN after the comment carries
`--network=none`) exits 0.
