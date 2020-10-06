# CKS-Certified-Kubernetes-Security-Specialist

## Cluster Setup – 10%

Use Network security policies to restrict cluster level access
	https://kubernetes.io/docs/concepts/services-networking/network-policies/
	https://kubernetes.io/docs/tasks/administer-cluster/securing-a-cluster/#restricting-network-access
Use CIS benchmark to review the security configuration of Kubernetes components (etcd, kubelet, kubedns, kubeapi)
	CIS Benchmark Kubernetes
Properly set up Ingress objects with security control
	https://kubernetes.io/docs/concepts/services-networking/ingress/#tls
	https://kubernetes.github.io/ingress-nginx/user-guide/tls/
Protect node metadata and endpoints
	https://cloud.google.com/kubernetes-engine/docs/how-to/protecting-cluster-metadata
	https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster
	https://kubernetes.io/docs/tasks/administer-cluster/securing-a-cluster/#restricting-cloud-metadata-api-access
	Falco check webinar??
Minimize use of, and access to, GUI elements
	https://kubernetes.io/docs/tasks/access-application-cluster/web-ui-dashboard/
	https://github.com/kubernetes/dashboard/blob/master/docs/user/access-control/creating-sample-user.md
Verify platform binaries before deploying
	https://github.com/kubernetes/kubernetes/releases
	sha256sum (https://help.ubuntu.com/community/HowToSHA256SUM)

Cluster Hardening – 15%

Restrict access to Kubernetes API
	https://kubernetes.io/docs/reference/access-authn-authz/controlling-access/
Use Role Based Access Controls to minimize exposure
	https://kubernetes.io/docs/reference/access-authn-authz/rbac/
Exercise caution in using service accounts e.g. disable defaults, minimize permissions on newly created ones
	https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/
	https://kubernetes.io/docs/reference/access-authn-authz/rbac/#default-roles-and-role-bindings
Update Kubernetes frequently
	https://kubernetes.io/docs/tasks/administer-cluster/kubeadm/kubeadm-upgrade/

System Hardening – 15%

Minimize host OS footprint (reduce attack surface)
	https://blog.sonatype.com/kubesecops-kubernetes-security-practices-you-should-follow#:~:text=Reduce%20Kubernetes%20Attack%20Surfaces
Minimize IAM roles
	
Minimize external access to the network
	firewall
Appropriately use kernel hardening tools such as AppArmor, seccomp
	

Minimize Microservice Vulnerabilities – 20%

Setup appropriate OS level security domains e.g. using PSP, OPA, security contexts
	https://kubernetes.io/docs/concepts/policy/pod-security-policy/
	https://kubernetes.io/blog/2019/08/06/opa-gatekeeper-policy-and-governance-for-kubernetes/
	https://kubernetes.io/docs/tasks/configure-pod-container/security-context/
Manage Kubernetes secrets
	https://kubernetes.io/docs/concepts/configuration/secret/
Use container runtime sandboxes in multi-tenant environments (e.g. gvisor, kata containers)
	https://katacontainers.io/
	https://github.com/google/gvisor
Implement pod to pod encryption by use of mTLS
	https://istio.io/latest/docs/tasks/security/authentication/authn-policy/#auto-mutual-tls

Supply Chain Security – 20%

Minimize base image footprint
	https://hackernoon.com/tips-to-reduce-docker-image-sizes-876095da3b34
Secure your supply chain: whitelist allowed registries, sign and validate images
	https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/
	https://stackoverflow.com/questions/54463125/how-to-reject-docker-registries-in-kubernetes
	https://docs.docker.com/engine/security/trust/content_trust/
	https://docs.docker.com/engine/reference/commandline/trust_sign/
	https://docs.docker.com/engine/reference/commandline/trust_inspect/
	OPA??
Use static analysis of user workloads (e.g.Kubernetes resources, Docker files)
	??
Scan images for known vulnerabilities
	??

Monitoring, Logging and Runtime Security – 20%

Perform behavioral analytics of syscall process and file activities at the host and container level to detect malicious activities
	https://falco.org/
	https://v1-16.docs.kubernetes.io/docs/tasks/debug-application-cluster/falco/
Detect threats within physical infrastructure, apps, networks, data, users and workloads
	??
Detect all phases of attack regardless where it occurs and how it spreads
	??
Perform deep analytical investigation and identification of bad actors within environment
	??
Ensure immutability of containers at runtime
	??
Use Audit Logs to monitor access
	https://kubernetes.io/docs/tasks/debug-application-cluster/audit/
