

# CKS Exam Preparation

In order to take the CKS exam, you must have **Valid CKA certification** to demonstrate you possess sufficient Kubernetes expertise. If you do not have passed CKA exam, here you find my learn path for that: [CKALearn](https://epa.ms/CKALearn) As firt to understand are you for that exam or not plese try to do that tas:  [**Securing a Cluster**](https://kubernetes.io/docs/tasks/administer-cluster/securing-a-cluster/) of the official K8s documentation.

## Usefull courses:

- Linux Academy:  [Kubernetes Security (Advanced Concepts)](https://linuxacademy.com/cp/modules/view/id/354)
- Linux Academy: [Kubernetes Security](https://linuxacademy.com/cp/modules/view/id/302)

## Cluster Setup – 10%

- Use Network security policies to restrict cluster level access
  - https://kubernetes.io/docs/concepts/services-networking/network-policies/
  - https://kubernetes.io/docs/tasks/administer-cluster/securing-a-cluster/#restricting-network-access
  - https://kubernetes.io/docs/tasks/administer-cluster/declare-network-policy/
  - https://github.com/ahmetb/kubernetes-network-policy-recipes
- Use CIS benchmark to review the security configuration of Kubernetes components (etcd, kubelet, kubedns, kubeapi)
  - CIS Benchmark Kubernetes
  - Default GKE cluster results: https://cloud.google.com/kubernetes-engine/docs/concepts/cis-benchmarks#status
- Properly set up Ingress objects with security control
  - https://kubernetes.io/docs/concepts/services-networking/ingress/#tls
  - https://kubernetes.github.io/ingress-nginx/user-guide/tls/
  - https://github.com/kubernetes/ingress-nginx/blob/master/docs/user-guide/tls.md
- Protect node metadata and endpoints
  - https://cloud.google.com/kubernetes-engine/docs/how-to/protecting-cluster-metadata
  - https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster
  - https://kubernetes.io/docs/tasks/administer-cluster/securing-a-cluster/#restricting-cloud-metadata-api-access
  - https://blog.cloud66.com/setting-up-secure-endpoints-in-kubernetes/
  - <mark>[AWS] Protecting metadata - iptables rule: https://docs.aws.amazon.com/eks/latest/userguide/restrict-ec2-credential-access.html</mark>
  - Falco webinar (just a demo): [Intro to Falco: Intrusion Detection for Containers - Shane Lawrence, Shopify](https://youtu.be/rBqBrYESryY?list=PLj6h78yzYM2O1wlsM-Ma-RYhfT5LKq0XC&t=1033)
- Minimize use of, and access to, GUI elements
  - https://kubernetes.io/docs/tasks/access-application-cluster/web-ui-dashboard/
  - https://github.com/kubernetes/dashboard/blob/master/docs/user/access-control/README.md
  - https://github.com/kubernetes/dashboard/blob/master/docs/user/access-control/creating-sample-user.md
  - https://blog.heptio.com/on-securing-the-kubernetes-dashboard-16b09b1b7aca
- Verify platform binaries before deploying
  - https://github.com/kubernetes/kubernetes/releases
  - sha256sum (https://help.ubuntu.com/community/HowToSHA256SUM)

## Cluster Hardening – 15%

- Restrict access to Kubernetes API
  - https://kubernetes.io/docs/reference/access-authn-authz/controlling-access/
  - (mentioned, but gust a general precautions) https://cloud.google.com/anthos/gke/docs/on-prem/how-to/hardening-your-cluster
- Use Role Based Access Controls to minimize exposure
  - https://kubernetes.io/docs/reference/access-authn-authz/rbac/
  - <mark>https://github.com/David-VTUK/CKA-StudyGuide/blob/master/RevisionTopics/Part-5-Security.md</mark>
- Exercise caution in using service accounts e.g. disable defaults, minimize permissions on newly created ones
  - https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/
  - https://kubernetes.io/docs/reference/access-authn-authz/rbac/#default-roles-and-role-bindings
  - [Understand Role Based Access Control in Kubernetes](https://www.youtube.com/watch?v=G3R24JSlGjY)
  - https://kubernetes.io/docs/reference/access-authn-authz/authorization/#authorization-modules
  - https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/#use-the-default-service-account-to-access-the-api-server
    - Other:
    - Get SA token: https://docs.armory.io/docs/armory-admin/manual-service-account/
    - https://thenewstack.io/a-practical-approach-to-understanding-kubernetes-authentication/ 
    - https://thenewstack.io/kubernetes-access-control-exploring-service-accounts/ 
    - https://www.cyberark.com/resources/threat-research-blog/securing-kubernetes-clusters-by-eliminating-risky-permissions
- Update Kubernetes frequently
  - https://kubernetes.io/docs/tasks/administer-cluster/kubeadm/kubeadm-upgrade/

## System Hardening – 15%

- Minimize host OS footprint (reduce attack surface)
  - https://blog.sonatype.com/kubesecops-kubernetes-security-practices-you-should-follow#:~:text=Reduce%20Kubernetes%20Attack%20Surfaces
  - <mark>CIS Benchmark "CIS Distribution Independent Linux" (https://www.cisecurity.org/benchmark/distribution_independent_linux/)</mark>
- Minimize IAM roles
- Minimize external access to the network
  - (Host-Level firewall) https://help.replicated.com/community/t/managing-firewalls-with-ufw-on-kubernetes/230
  - <mark>(iptables cheat sheet) https://gist.github.com/davydany/0ad377f6de3c70056d2bd0f1549e1017</mark>
- Appropriately use kernel hardening tools such as AppArmor, seccomp
  - https://kubernetes.io/docs/tutorials/clusters/apparmor/ 
  - https://kubernetes.io/docs/tutorials/clusters/seccomp/	

## Minimize Microservice Vulnerabilities – 20%

- Setup appropriate OS level security domains e.g. using PSP, OPA, security contexts
  - https://kubernetes.io/docs/concepts/policy/pod-security-policy/
  - https://kubernetes.io/blog/2019/08/06/opa-gatekeeper-policy-and-governance-for-kubernetes/
  - https://kubernetes.io/docs/tasks/configure-pod-container/security-context/
- Manage Kubernetes secrets
  - https://kubernetes.io/docs/concepts/configuration/secret/
  - <mark>Secret Encryption (etcd) https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/</mark>
- Use container runtime sandboxes in multi-tenant environments (e.g. gvisor, kata containers)
  - https://katacontainers.io/
  - https://github.com/google/gvisor
- Implement pod to pod encryption by use of mTLS
  - <mark>https://kubernetes.io/docs/tasks/tls/managing-tls-in-a-cluster/</mark>
  - <mark>https://developer.ibm.com/technologies/containers/tutorials/istio-security-mtls/</mark>
  - <mark>https://www.istioworkshop.io/11-security/01-mtls/</mark>
  - https://istio.io/latest/docs/tasks/security/authentication/authn-policy/#auto-mutual-tls

## Supply Chain Security – 20%

- Minimize base image footprint
  - <mark>https://cloud.google.com/blog/products/gcp/7-best-practices-for-building-containers</mark>
  - https://hackernoon.com/tips-to-reduce-docker-image-sizes-876095da3b34
- Secure your supply chain: whitelist allowed registries, sign and validate images
  - https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/
  - https://stackoverflow.com/questions/54463125/how-to-reject-docker-registries-in-kubernetes
  - https://docs.docker.com/engine/security/trust/content_trust/
  - https://docs.docker.com/engine/reference/commandline/trust_sign/
  - https://docs.docker.com/engine/reference/commandline/trust_inspect/
  - <mark>OPA registry restriction https://www.openpolicyagent.org/docs/latest/kubernetes-primer/</mark>
- Use static analysis of user workloads (e.g.Kubernetes resources, Docker files)
  - <mark>kybehunter https://github.com/aquasecurity/kube-hunter</mark>
- Scan images for known vulnerabilities
  - <mark>clair https://github.com/quay/clair</mark>
  - <mark></mark>

## Monitoring, Logging and Runtime Security – 20%

- Perform behavioral analytics of syscall process and file activities at the host and container level to detect malicious activities
  - https://falco.org/
  - https://v1-16.docs.kubernetes.io/docs/tasks/debug-application-cluster/falco/
- Detect threats within physical infrastructure, apps, networks, data, users and workloads
  - ??
- Detect all phases of attack regardless where it occurs and how it spreads
  - ??
- Perform deep analytical investigation and identification of bad actors within environment
  - ??
- Ensure immutability of containers at runtime
  - ??
- Use Audit Logs to monitor access
  - https://kubernetes.io/docs/tasks/debug-application-cluster/audit/

