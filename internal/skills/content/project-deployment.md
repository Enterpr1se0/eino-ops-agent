# Project Deployment

Use this workflow to deploy an arbitrary project without assuming its language, process manager, or packaging model.

1. Inspect the repository or uploaded workspace: README, manifest files, Dockerfile, Compose files, build scripts, migrations, environment templates, health checks and existing deployment documentation.
2. Inspect the target host read-only: OS/architecture, disk capacity, ports, installed runtime/container engine, existing service, filesystem ownership and current version.
3. Produce a plan containing source revision, build location, artifact, target paths, configuration references, service lifecycle, health verification and rollback. Never include secret values.
4. Prefer immutable/versioned releases and an atomic `current` symlink. Preserve the previous release until verification completes.
5. Submit changes as small audited operations. File writes, package installation, service restart, container changes and symlink switches require approval.
6. Run migrations only when explicitly detected and described; treat irreversible migrations as Critical.
7. Verify process state, listening port, health endpoint and a bounded log window. If verification fails, propose the predeclared rollback rather than improvising destructive cleanup.
8. Report deployed revision, commands and run IDs, verification evidence, rollback readiness and pending concerns.

The SSH tools are universal; Docker, systemd, static files and custom build systems are selected from evidence rather than hard-coded as the only options.
