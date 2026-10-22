# Phase 1 — Zero-Trust Kubernetes

Defense in depth across three layers. Each assumes the one above it may be bypassed.

| Layer             | Control                                          | File                                  | Enforces                                                                                                 |
| ----------------- | ------------------------------------------------ | ------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| L3/L4 network     | default-deny NetworkPolicy + explicit allows     | `base/networkpolicy.yaml`             | pods reach only DNS, the mesh gateway, and same-app pods in their own namespace                          |
| L7 identity/authz | Istio STRICT mTLS + deny-all AuthorizationPolicy | `istio/*.yaml`                        | every in-mesh call is mutually authenticated (SPIFFE); only the ingress gateway identity may hit the API |
| Runtime           | Tetragon eBPF exec enforcement                   | `runtime/tetragon-tracingpolicy.yaml` | SIGKILLs any shell/interpreter exec inside the workload (post-exploitation signal)                       |

Workload itself: non-root, read-only rootfs, all caps dropped, no SA token, seccomp RuntimeDefault, `restricted` PSS (`base/deployment.yaml`, `base/namespaces.yaml`).

## Apply

```sh
# 1. base workload + network isolation (per tenant namespace)
kubectl apply -k deploy/kubernetes/base -n tenant-a

# 2. mesh mTLS (mesh-wide) + L7 authz (per namespace)
kubectl apply -f deploy/kubernetes/istio/peer-authentication.yaml
kubectl apply -f deploy/kubernetes/istio/authorization-policy.yaml

# 3. eBPF runtime enforcement (requires Tetragon installed)
kubectl apply -f deploy/kubernetes/runtime/tetragon-tracingpolicy.yaml
```

The istio/ and runtime/ manifests target `tenant-a`; duplicate with the namespace swapped for `tenant-b`.

## Verify the trust boundary

```sh
# mTLS is strict — plaintext curl from a non-mesh pod should be refused:
kubectl run probe --image=curlimages/curl -n tenant-a --rm -it -- curl -s security-api        # connection reset
# exec enforcement — opening a shell in the pod should be killed instantly:
kubectl exec -n tenant-a deploy/security-api -- /bin/sh                                        # SIGKILL
```

Manifest syntax is covered by `tests/test_k8s_manifests.py`.
