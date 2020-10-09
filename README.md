

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
  - <mark>Good NP description with examples: https://medium.com/@reuvenharrison/an-introduction-to-kubernetes-network-policies-for-security-people-ba92dd4c809d</mark>
  - <mark>NP best practices: https://medium.com/@tufin/best-practices-for-kubernetes-network-policies-2b643c4b1aa</mark>
  - <mark>Network Policy Visualizer https://orca.tufin.io/netpol/</mark>
  - <mark>https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.19/#networkpolicy-v1-networking-k8s-io</mark>
  - Notes:
    > podSelector: This selects particular Pods in the **same namespace as the NetworkPolicy** which should be allowed as ingress sources or egress destinations.
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
  - <mark>Notes:
    > ```
    > egress:
    > - to:
    >   - ipBlock:
    >       cidr: 0.0.0.0/0
    >       except:
    >       - 169.254.169.254/32
    > ```
    > </mark>
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
  - <mark>Restrict access to API via NP: https://medium.com/@tufin/protecting-your-kubernetes-api-server-5eefeea4cf8a</mark>
  - (mentioned, but gust a general precautions) https://cloud.google.com/anthos/gke/docs/on-prem/how-to/hardening-your-cluster
- Use Role Based Access Controls to minimize exposure
  - https://kubernetes.io/docs/reference/access-authn-authz/rbac/
  - <mark>https://github.com/David-VTUK/CKA-StudyGuide/blob/master/RevisionTopics/Part-5-Security.md</mark>
- Exercise caution in using service accounts e.g. disable defaults, minimize permissions on newly created ones
  - https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/
  - https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/#use-the-default-service-account-to-access-the-api-server
  - https://kubernetes.io/docs/reference/access-authn-authz/rbac/#default-roles-and-role-bindings
  - [Understand Role Based Access Control in Kubernetes](https://www.youtube.com/watch?v=G3R24JSlGjY)
  - https://kubernetes.io/docs/reference/access-authn-authz/authorization/#authorization-modules
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
  - **Grant least privilege**
- Minimize external access to the network
  - (Host-Level firewall **ufw (_uncomplicated firewall_)**) https://help.replicated.com/community/t/managing-firewalls-with-ufw-on-kubernetes/230
  - <mark>**ufw** quick https://www.linode.com/docs/security/firewalls/configure-firewall-with-ufw/</mark>
  - <mark>(**iptables** cheat sheet) https://gist.github.com/davydany/0ad377f6de3c70056d2bd0f1549e1017</mark>
- Appropriately use kernel hardening tools such as AppArmor, seccomp
  - https://kubernetes.io/docs/tutorials/clusters/apparmor/ 
  - https://kubernetes.io/docs/tutorials/clusters/seccomp/	

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

