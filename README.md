

# CKS Exam Preparation

In order to take the CKS exam, you must have **Valid CKA certification** to demonstrate you possess sufficient Kubernetes expertise. If you do not have passed CKA exam, here you find my learn path for that: [CKALearn](https://epa.ms/CKALearn) As firt to understand are you for that exam or not plese try to do that tas:  [**Securing a Cluster**](https://kubernetes.io/docs/tasks/administer-cluster/securing-a-cluster/) of the official K8s documentation.

## Usefull courses:

- Linux Academy:  [Kubernetes Security (Advanced Concepts)](https://linuxacademy.com/cp/modules/view/id/354)
- Linux Academy: [Kubernetes Security](https://linuxacademy.com/cp/modules/view/id/302)

## General security-related docs

- **GCP (GKE) General security guide** https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster

## Cluster Setup – 10%

- Use Network security policies to restrict cluster level access
  - **Main doc:** https://kubernetes.io/docs/concepts/services-networking/network-policies/
  - **Main task:** https://kubernetes.io/docs/tasks/administer-cluster/declare-network-policy/
  - **General practice:** https://kubernetes.io/docs/tasks/administer-cluster/securing-a-cluster/#restricting-network-access
  - **Official blog post:** https://kubernetes.io/blog/2017/10/enforcing-network-policies-in-kubernetes/
  - **NetworkPolicy API object reference:** https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.19/#networkpolicy-v1-networking-k8s-io
  - 3rd Party:
    - _NP Examples:_ https://github.com/ahmetb/kubernetes-network-policy-recipes
    - _Good NP description with examples:_ https://medium.com/@reuvenharrison/an-introduction-to-kubernetes-network-policies-for-security-people-ba92dd4c809d
    - _NP best practices:_ https://medium.com/@tufin/best-practices-for-kubernetes-network-policies-2b643c4b1aa
    - _[Playground] Network Policy Visualizer_ https://orca.tufin.io/netpol/
  - **Notes**:
    > podSelector: This selects particular Pods in the **same namespace as the NetworkPolicy** which should be allowed as ingress sources or egress destinations.
- Use CIS benchmark to review the security configuration of Kubernetes components (etcd, kubelet, kubedns, kubeapi)
  - 3rd Party:
    - _CIS Benchmark Kubernetes_
    - _kubebench (CNCF)_ https://github.com/aquasecurity/kube-bench#running-kube-bench
    - _Default GKE cluster results:_ https://cloud.google.com/kubernetes-engine/docs/concepts/cis-benchmarks#status
- Properly set up Ingress objects with security control
  - **Main doc (TLS):** https://github.com/kubernetes/ingress-nginx/blob/master/docs/user-guide/tls.md
  - **Main Concept (ingress, TLS):** https://kubernetes.io/docs/concepts/services-networking/ingress/#tls
  - **Main Concept (ingress controller, multiple controllers):** https://kubernetes.io/docs/concepts/services-networking/ingress-controllers/
  - **Create TLS secret:** https://kubernetes.io/docs/reference/generated/kubectl/kubectl-commands#-em-secret-tls-em-
- Protect node metadata and endpoints
  - **General:** https://kubernetes.io/docs/tasks/administer-cluster/securing-a-cluster/#restricting-cloud-metadata-api-access
  - 3rd Party:
    - _[Practical] Protecting metadata - **iptables rule**:_ https://docs.aws.amazon.com/eks/latest/userguide/restrict-ec2-credential-access.html
    - _GCP-specific metadata protection guide_ https://cloud.google.com/kubernetes-engine/docs/how-to/protecting-cluster-metadata
    - _Setting up secure endpoints in Kubernetes (might be not related):_ https://blog.cloud66.com/setting-up-secure-endpoints-in-kubernetes/
    - _Falco webinar (just a demo):_ [Intro to Falco: Intrusion Detection for Containers - Shane Lawrence, Shopify](https://youtu.be/rBqBrYESryY?list=PLj6h78yzYM2O1wlsM-Ma-RYhfT5LKq0XC&t=1033)
  - **Notes:**
    > ```
    > egress:
    > - to:
    >   - ipBlock:
    >       cidr: 0.0.0.0/0
    >       except:
    >       - 169.254.169.254/32
    > ```
- Minimize use of, and access to, GUI elements
  - **Main doc:** https://kubernetes.io/docs/tasks/access-application-cluster/web-ui-dashboard/
  - **Dashboard Access control:** https://github.com/kubernetes/dashboard/blob/master/docs/user/access-control/README.md
  - **Dashboard auth Step-by-Step:** https://github.com/kubernetes/dashboard/blob/master/docs/user/access-control/creating-sample-user.md
  - 3rd Party:
    - _[Long Read] On Securing the Kubernetes Dashboard:_ https://blog.heptio.com/on-securing-the-kubernetes-dashboard-16b09b1b7aca
- Verify platform binaries before deploying
  - **K8s Releases (with SHA checksums):** https://github.com/kubernetes/kubernetes/releases
  - 3rd Party:
    - _sha256sum_ (https://help.ubuntu.com/community/HowToSHA256SUM)

## Cluster Hardening – 15%

> **Main doc (and beyond):** https://kubernetes.io/docs/reference/access-authn-authz/

- Restrict access to Kubernetes API
  - **Main doc:** https://kubernetes.io/docs/reference/access-authn-authz/controlling-access/
  - 3rd Party:
    - _Restrict access to API via NP:_ https://medium.com/@tufin/protecting-your-kubernetes-api-server-5eefeea4cf8a
- Use Role Based Access Controls to minimize exposure
  - **Main doc:** https://kubernetes.io/docs/reference/access-authn-authz/rbac/
  - 3rd Party:
    - _[Practice] RBAC, PSP, NP, TLS, etc._ https://github.com/David-VTUK/CKA-StudyGuide/blob/master/RevisionTopics/Part-5-Security.md
- Exercise caution in using service accounts e.g. disable defaults, minimize permissions on newly created ones
  - **Main doc:** https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/
  - **[Task] Service Account use (+automountServiceAccountToken):** https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/#use-the-default-service-account-to-access-the-api-server
  - **Default Roles:** https://kubernetes.io/docs/reference/access-authn-authz/rbac/#default-roles-and-role-bindings
  - **Auth Modules:** https://kubernetes.io/docs/reference/access-authn-authz/authorization/#authorization-modules
  - 3rd Party:
    - _[Youtube] Understand Role Based Access Control in Kubernetes_ https://www.youtube.com/watch?v=G3R24JSlGjY
    - _Get SA token:_ https://docs.armory.io/docs/armory-admin/manual-service-account/
    - _Blogpost series:_
      - _[1/4] A Primer on Kubernetes Access Control_ https://thenewstack.io/a-primer-on-kubernetes-access-control/
      - _[2/4] A Practical Approach to Understanding Kubernetes Authentication_ https://thenewstack.io/a-practical-approach-to-understanding-kubernetes-authentication/
      - _[3/4] A Practical Approach to Understanding Kubernetes Authorization_ https://thenewstack.io/a-practical-approach-to-understanding-kubernetes-authorization/
      - _[4/4] Kubernetes Access Control: Exploring Service Accounts_ https://thenewstack.io/kubernetes-access-control-exploring-service-accounts/
    - _Securing Kubernetes Clusters by Eliminating Risky Permissions:_ https://www.cyberark.com/resources/threat-research-blog/securing-kubernetes-clusters-by-eliminating-risky-permissions
- Update Kubernetes frequently
  - **Main doc (kubeadm upgrade):** https://kubernetes.io/docs/tasks/administer-cluster/kubeadm/kubeadm-upgrade/
  - **Reference (kubeadm upgrade):** https://kubernetes.io/docs/reference/setup-tools/kubeadm/kubeadm-upgrade/

## System Hardening – 15%

- Minimize host OS footprint (reduce attack surface)
  - 3rd Party:
    - _[Blogpost] Reduce Kubernetes Attack Surfaces_ https://blog.sonatype.com/kubesecops-kubernetes-security-practices-you-should-follow#:~:text=Reduce%20Kubernetes%20Attack%20Surfaces
    - _CIS Benchmark "CIS Distribution Independent Linux"_ https://www.cisecurity.org/benchmark/distribution_independent_linux/
- Minimize IAM roles
  - 3rd Party:
    - [Common theory] Grant least privilege https://digitalguardian.com/blog/what-principle-least-privilege-polp-best-practice-information-security-and-compliance
- Minimize external access to the network
  - 3rd Party:
    - _Host-Level firewall **ufw (_uncomplicated firewall_)**_ https://help.replicated.com/community/t/managing-firewalls-with-ufw-on-kubernetes/230
    - _**ufw** quick-start_ https://www.linode.com/docs/security/firewalls/configure-firewall-with-ufw/
    - _**iptables** cheat sheet_ https://gist.github.com/davydany/0ad377f6de3c70056d2bd0f1549e1017
- Appropriately use kernel hardening tools such as AppArmor, seccomp
  - **Main doc (apparmor & k8s)** https://kubernetes.io/docs/tutorials/clusters/apparmor/ 
  - **Main doc (seccomp & k8s)** https://kubernetes.io/docs/tutorials/clusters/seccomp/	

## Minimize Microservice Vulnerabilities – 20%

- Setup appropriate OS level security domains e.g. using PSP, OPA, security contexts
  - **PSP:** https://kubernetes.io/docs/concepts/policy/pod-security-policy/
  - **Security Context:** https://kubernetes.io/docs/tasks/configure-pod-container/security-context/
  - 3rd Party:
    - **OPA (Blog):** https://kubernetes.io/blog/2019/08/06/opa-gatekeeper-policy-and-governance-for-kubernetes/
    - **OPA:** https://www.openpolicyagent.org/docs/latest/kubernetes-primer/
- Manage Kubernetes secrets
  - **Main doc:** https://kubernetes.io/docs/concepts/configuration/secret/
  - **Secret Encryption (etcd)** https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/
  - 3rd Party:
    - _Kubernetes-Secrets-Store-CSI-Driver_ (used by 3rd-party secret stores such as Vault, KeyVault etc.) https://github.com/kubernetes-sigs/secrets-store-csi-driver
    - _Bitnami Sealed Secrets_ https://github.com/bitnami-labs/sealed-secrets
    - Demo for Vault integration: https://www.youtube.com/watch?v=IznsHhKL428&ab_channel=VMwareCloudNativeApps
- Use container runtime sandboxes in multi-tenant environments (e.g. gvisor, kata containers)
  - 3rd Party:
    - _kata containers_ https://katacontainers.io/
    - _gvisor_ https://github.com/google/gvisor
- Implement pod to pod encryption by use of mTLS
  - **Main doc:** https://kubernetes.io/docs/tasks/tls/managing-tls-in-a-cluster/
  - 3rd Party:
    - _Istio:_ https://istio.io/latest/docs/tasks/security/authentication/authn-policy/#auto-mutual-tls
    - _Istio:_ https://developer.ibm.com/technologies/containers/tutorials/istio-security-mtls/
    - _Istio:_ https://www.istioworkshop.io/11-security/01-mtls/

## Supply Chain Security – 20%

- Minimize base image footprint
  - 3rd Party:
    - _Best practices_ https://cloud.google.com/blog/products/gcp/7-best-practices-for-building-containers
    - _"Distroless" Docker Images_ https://github.com/GoogleContainerTools/distroless
    - https://hackernoon.com/tips-to-reduce-docker-image-sizes-876095da3b34
- Secure your supply chain: whitelist allowed registries, sign and validate images
  - **Admission controllers** https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/
  - **One more link**: https://kubernetes.io/blog/2019/03/21/a-guide-to-kubernetes-admission-controllers/
  - 3rd Party:
    - _OPA registry restriction:_ https://www.openpolicyagent.org/docs/latest/kubernetes-primer/
    - _ImagePolicyWebhook (controller itself - custom):_ https://stackoverflow.com/questions/54463125/how-to-reject-docker-registries-in-kubernetes
      - _ImagePolicyWebhook controller example:_ https://github.com/flavio/kube-image-bouncer
    - _Docker content trust_ https://docs.docker.com/engine/security/trust/
      - https://docs.docker.com/engine/reference/commandline/trust_sign/
      - https://docs.docker.com/engine/reference/commandline/trust_inspect/
- Use static analysis of user workloads (e.g.Kubernetes resources, Docker files)
  - 3rd Party:
    - _CNCF kubehunter_ https://github.com/aquasecurity/kube-hunter
- Scan images for known vulnerabilities
  - 3rd Party:
    - _clair_ https://github.com/quay/clair

## Monitoring, Logging and Runtime Security – 20%

- Perform behavioral analytics of syscall process and file activities at the host and container level to detect malicious activities
  - **Obsoleted** https://v1-16.docs.kubernetes.io/docs/tasks/debug-application-cluster/falco/
  - 3rd Party:
    - _Falco (CNCF):_ https://falco.org/
- Detect threats within physical infrastructure, apps, networks, data, users and workloads
  - ??
- Detect all phases of attack regardless where it occurs and how it spreads
  - 3rd Party:
    - _Just a concept:_ https://www.dnvgl.com/article/the-seven-phases-of-a-cyber-attack-118270
- Perform deep analytical investigation and identification of bad actors within environment
  - ??
- Ensure immutability of containers at runtime
  - ??
- Use Audit Logs to monitor access
  - **Main doc:** https://kubernetes.io/docs/tasks/debug-application-cluster/audit/

