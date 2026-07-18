# Project Deployment

Use this workflow to deploy an arbitrary project without assuming its language, process manager, or packaging model.

1. Inspect the repository or uploaded workspace: README, manifest files, Dockerfile, Compose files, build scripts, migrations, environment templates, health checks and existing deployment documentation.
2. Inspect the target host read-only: OS/architecture, disk capacity, ports, installed runtime/container engine, existing service, filesystem ownership and current version.
3. Produce a plan containing source revision, build location, release package, target paths, configuration references, service lifecycle, health verification and rollback. Never include secret values.
4. Prefer immutable/versioned releases and an atomic `current` symlink. Preserve the previous release until verification completes.
5. Submit changes as small audited operations. For configuration files, read the SHA256 first and use the transactional configuration tool so the approval binds the version, diff, validator and protected backup. A conflict requires a fresh read, never a blind overwrite.
6. When source is in an allowlisted Workspace, use workspace read/search/patch tools. To transfer a file, read its SHA256 and use `workspace_file_upload` so one approval binds the Workspace path, content version, target host, and remote path. For multi-host deployment, submit one version-bound transfer per host. Workspace access never permits a local shell or paths outside its configured root.
7. Run migrations only when explicitly detected and described; treat irreversible migrations as Critical.
8. Verify process state, listening port, health endpoint and a bounded log window. If verification fails, use the audited backup or predeclared rollback rather than improvising destructive cleanup.
9. Report deployed revision, commands and run IDs, file operation IDs, verification evidence, rollback readiness and pending concerns.

The SSH tools are universal; Docker, systemd, static files and custom build systems are selected from evidence rather than hard-coded as the only options.
