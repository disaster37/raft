# Kubernetes deployment

## StatefulSet

```yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: raft
spec:
  serviceName: raft-headless
  replicas: 3
  podManagementPolicy: Parallel
  selector:
    matchLabels: {app: raft}
  template:
    metadata:
      labels: {app: raft}
    spec:
      dnsPolicy: None
      dnsConfig:
        nameservers: ["169.254.20.10"]
        searches: ["raft.svc.cluster.local", "svc.cluster.local", "cluster.local"]
        options:
          - name: ndots
            value: "1"
      containers:
        - name: raft
          image: ghcr.io/disaster37/go-raft:latest
          ports:
            - {name: raft, containerPort: 8081}
            - {name: http, containerPort: 8080}
          env:
            - {name: POD_NAME, valueFrom: {fieldRef: {fieldPath: metadata.name}}}
            - {name: POD_NAMESPACE, valueFrom: {fieldRef: {fieldPath: metadata.namespace}}}
          readinessProbe:
            httpGet: {path: /readyz, port: http}
            periodSeconds: 5
          startupProbe:
            httpGet: {path: /startup, port: http}
            failureThreshold: 60
            periodSeconds: 2
          livenessProbe:
            httpGet: {path: /livez, port: http}
            periodSeconds: 10
          volumeMounts:
            - {name: data, mountPath: /var/lib/raft}
  volumeClaimTemplates:
    - metadata: {name: data}
      spec:
        accessModes: [ReadWriteOnce]
        resources: {requests: {storage: 10Gi}}
```

## Headless Service

```yaml
apiVersion: v1
kind: Service
metadata:
  name: raft-headless
spec:
  clusterIP: None
  publishNotReadyAddresses: true
  selector: {app: raft}
  ports:
    - {name: raft, port: 8081, targetPort: raft}
```

`publishNotReadyAddresses: true` lets peers resolve each other before
readiness, which is required for bootstrap.

## DNS cache mitigation

Use fully-qualified names (`<pod>.<headless>.<ns>.svc.cluster.local`) and
`ndots: 1` to avoid CoreDNS/NodeLocal DNSCache negative-cache poisoning. The
transport re-resolves DNS on every dial and retries `ECONNREFUSED`.

## RBAC

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: raft}
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get", "create", "update"]
  - apiGroups: ["apps"]
    resources: ["statefulsets"]
    verbs: ["get"]
```

Bind the Role to the StatefulSet's ServiceAccount. The Secret holds the CA
private key, so restrict access to this ServiceAccount only.

## Probes

- `/startup`: 200 once the node is a voter/leader.
- `/readyz`: 200 when `IsCleanState` is true (settled Leader/Follower, no
  pending FSM work, follower has recent leader contact).
- `/livez`: always 200 while the process is alive.
