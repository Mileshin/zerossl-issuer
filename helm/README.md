# Helm Chart: zerossl-cert-manager

This Helm chart enables deploying either a **CronJob** or a **DaemonSet** based on a configuration parameter. It includes support for environment variables, cleanup logic, and RBAC permissions.

---

## Configuration

### Environment Variables

The following environment variables are used to ensure proper operation of the application:

- `ZEROSSL_API_KEY`
- `LOG_LEVEL`
- `RENEWAL_THRESHOLD_DAYS`

These are set within the pod environment.

---

### Type Selection

The deployment type is controlled by the `type` value in `values.yaml`:

```yaml
type: cronjob  # or daemonset
```

---

### CronJob Configuration

```yaml
cronjob:
  schedule: "49 15 * * *"  # Executes daily at 15:49 UTC
  sleepDuration: 300       # Time (in seconds) to wait before deleting the DaemonSet
```

If `type` is set to `cronjob`, the chart:

- Uses the image `k8s.gcr.io/pause:3.5`
- Schedules the job at the defined interval
- Waits for `sleepDuration` before cleaning up the DaemonSet

---

### DaemonSet Configuration

```yaml
daemonset:
  activeDeadlineSeconds: 600  # Maximum run duration in seconds
```

If `type` is set to `daemonset`, the chart:

- Uses the image `busybox:1.37.0`
- Executes a command to sleep for the defined duration

---

### Helm Template Logic

The following snippet demonstrates how the chart dynamically switches between CronJob and DaemonSet:

```gotemplate
{{- if eq .Values.type "cronjob" }}
  image: k8s.gcr.io/pause:3.5
{{- else if eq .Values.type "daemonset" }}
  image: busybox:1.37.0
  command: ["sh", "-c", "echo \"now $(date), sleep {{ .Values.daemonset.activeDeadlineSeconds }} seconds\"; sleep {{ .Values.daemonset.activeDeadlineSeconds }}"]
{{- else }}
  {{ fail "Invalid value for type. Use cronjob or daemonset." }}
{{- end }}
```

---

### Cleanup Logic

If deployed as a CronJob, the chart automatically cleans up the associated DaemonSet after execution.

---

### RBAC Configuration

This chart includes the following RBAC resources:

- **Roles** and **RoleBindings** for:
  - Listing, creating, and deleting DaemonSets and CronJobs
- **ClusterRole** for:
  - Accessing node information