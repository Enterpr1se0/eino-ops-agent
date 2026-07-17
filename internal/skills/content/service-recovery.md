# Service Recovery

Use this workflow when a known service is degraded or unavailable.

1. Confirm the symptom from outside and inside the host. Identify the service manager, process, port and dependency chain.
2. Inspect status, recent bounded logs, exit code, resource pressure and the most recent configuration or deployment change.
3. Prefer fixing the cause over restarting. A restart is a state change and requires approval.
4. If a restart is justified, specify impact, expected duration, exact verification and rollback/escalation path.
5. For repeated crash loops, stop after collecting evidence; do not repeatedly restart.
6. Verify health, error rate, port state, process stability and logs after recovery.
7. Preserve all run IDs and summarize the incident timeline for audit review.

Never disable security controls, erase logs, rotate credentials, or remove data as a recovery shortcut.
