# AutoScaling AWS

Tutorial seguindo a documentação [https://rancher.com/docs/rancher/v2.6/en/cluster-admin/cluster-autoscaler/amazon/](https://rancher.com/docs/rancher/v2.6/en/cluster-admin/cluster-autoscaler/amazon/)

![architecture.png](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/9331e799-4e27-4cb4-ad6e-4517c5e4d9f1/architecture.png)

> ⚠️ Itens em cor verde devem ser alterados de acordo com o seu ambiente
> 

---

### Dicionário AWS

> Nomencaltura:
> 
> 
> Profile = Roles
> 
- **Info do cluster**
    
    Informações que devem ser anotadas: 
    
    Comando para adicionar o WORKER: `sudo docker run -d --privileged --restart=unless-stopped --net=host -v /etc/kubernetes:/etc/kubernetes -v /var/run:/var/run rancher/rancher-agent:v2.6.5 --server [https://rancher.gbrlins.com](https://rancher.gbrlins.com/) --token rlprzbhfhrnpk75x2wkfn4rrj7zfvdg7szff24xz6ntllj6xrhll45 --ca-checksum bd4def8368963646423e158f985a7569bfacbbaa21028b2e228123886f2ed91f --worker`
    
    Comando para adicionar o MASTER: `sudo docker run -d --privileged --restart=unless-stopped --net=host -v /etc/kubernetes:/etc/kubernetes -v /var/run:/var/run rancher/rancher-agent:v2.6.5 --server [https://rancher.gbrlins.com](https://rancher.gbrlins.com/) --token rlprzbhfhrnpk75x2wkfn4rrj7zfvdg7szff24xz6ntllj6xrhll45 --ca-checksum bd4def8368963646423e158f985a7569bfacbbaa21028b2e228123886f2ed91f --etcd --controlplane`
    
    clusterID: **`kubernetes.io/cluster/c-w7bkk`**
    
    clusterName: **`k8s.io/cluster-autoscaler/cluster-autoscaler`**
    
    > Dentre vários formas, é possível verificar o *clusterID* através do link pelo próprio Rancher do tipo [https://rancher.gbrlins.com/dashboard/c/c-w7bkk/explorer/node](https://rancher.gbrlins.com/dashboard/c/c-w7bkk/explorer/node)
    > 
- Scripts para serem executados durante criação das VMs:
    - K8sMasterUserData
        
        ```bash
        #!/bin/bash -x
        cat <<EOF > /etc/sysctl.d/90-kubelet.conf
        vm.overcommit_memory = 1
        vm.panic_on_oom = 0
        kernel.panic = 10
        kernel.panic_on_oops = 1
        kernel.keys.root_maxkeys = 1000000
        kernel.keys.root_maxbytes = 25000000
        EOF
        sysctl -p /etc/sysctl.d/90-kubelet.conf
        
        curl -sL https://releases.rancher.com/install-docker/19.03.sh | sh
        sudo usermod -aG docker ubuntu
        
        TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
        PRIVATE_IP=$(curl -H "X-aws-ec2-metadata-token: ${TOKEN}" -s http://169.254.169.254/latest/meta-data/local-ipv4)
        PUBLIC_IP=$(curl -H "X-aws-ec2-metadata-token: ${TOKEN}" -s http://169.254.169.254/latest/meta-data/public-ipv4)
        K8S_ROLES="--etcd --controlplane"
        
        sudo docker run -d --privileged --restart=unless-stopped --net=host -v /etc/kubernetes:/etc/kubernetes -v /var/run:/var/run rancher/rancher-agent:v2.6.5 --server [https://rancher.gbrlins.com](https://rancher.gbrlins.com/) --token rlprzbhfhrnpk75x2wkfn4rrj7zfvdg7szff24xz6ntllj6xrhll45 --ca-checksum bd4def8368963646423e158f985a7569bfacbbaa21028b2e228123886f2ed91f --address ${PUBLIC_IP} --internal-address ${PRIVATE_IP} ${K8S_ROLES}
        ```
        
    - K8sWorkerUserData
        
        ```bash
        #!/bin/bash -x
        cat <<EOF > /etc/sysctl.d/90-kubelet.conf
        vm.overcommit_memory = 1
        vm.panic_on_oom = 0
        kernel.panic = 10
        kernel.panic_on_oops = 1
        kernel.keys.root_maxkeys = 1000000
        kernel.keys.root_maxbytes = 25000000
        EOF
        sysctl -p /etc/sysctl.d/90-kubelet.conf
        
        curl -sL https://releases.rancher.com/install-docker/19.03.sh | sh
        sudo usermod -aG docker ubuntu
        
        TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
        PRIVATE_IP=$(curl -H "X-aws-ec2-metadata-token: ${TOKEN}" -s http://169.254.169.254/latest/meta-data/local-ipv4)
        PUBLIC_IP=$(curl -H "X-aws-ec2-metadata-token: ${TOKEN}" -s http://169.254.169.254/latest/meta-data/public-ipv4)
        K8S_ROLES="--worker"
        
        sudo docker run -d --privileged --restart=unless-stopped --net=host -v /etc/kubernetes:/etc/kubernetes -v /var/run:/var/run rancher/rancher-agent:v2.6.5 --server [https://rancher.gbrlins.com](https://rancher.gbrlins.com/) --token rlprzbhfhrnpk75x2wkfn4rrj7zfvdg7szff24xz6ntllj6xrhll45 --ca-checksum bd4def8368963646423e158f985a7569bfacbbaa21028b2e228123886f2ed91f --address ${PUBLIC_IP} --internal-address ${PRIVATE_IP} ${K8S_ROLES}
        ```
        

---

# Passo a passo

## Configuração na AWS

1. Criar um cluster no Rancher do tipo “*custom*” e selecionar AMAZON como provider.
2. Criar uma *Policy* no IAM com o nome “**K8sAutoscalerProfile**” com o seguinte JSON:

```json
{
      "Version": "2012-10-17",
      "Statement": [
          {
              "Effect": "Allow",
              "Action": [
                  "autoscaling:DescribeAutoScalingGroups",
                  "autoscaling:DescribeAutoScalingInstances",
                  "autoscaling:DescribeLaunchConfigurations",
                  "autoscaling:SetDesiredCapacity",
                  "autoscaling:TerminateInstanceInAutoScalingGroup",
                  "autoscaling:DescribeTags",
                  "autoscaling:DescribeLaunchConfigurations",
                  "ec2:DescribeLaunchTemplateVersions"
              ],
              "Resource": [
                  "*"
              ]
          }
      ]
  }
```

1. Criar outra *Policy* no IAM com o nome “**K8sMasterProfile**” com o seguinte JSON:

```json
{
      "Version": "2012-10-17",
      "Statement": [
          {
              "Effect": "Allow",
              "Action": [
                  "autoscaling:DescribeAutoScalingGroups",
                  "autoscaling:DescribeLaunchConfigurations",
                  "autoscaling:DescribeTags",
                  "ec2:DescribeInstances",
                  "ec2:DescribeRegions",
                  "ec2:DescribeRouteTables",
                  "ec2:DescribeSecurityGroups",
                  "ec2:DescribeSubnets",
                  "ec2:DescribeVolumes",
                  "ec2:CreateSecurityGroup",
                  "ec2:CreateTags",
                  "ec2:CreateVolume",
                  "ec2:ModifyInstanceAttribute",
                  "ec2:ModifyVolume",
                  "ec2:AttachVolume",
                  "ec2:AuthorizeSecurityGroupIngress",
                  "ec2:CreateRoute",
                  "ec2:DeleteRoute",
                  "ec2:DeleteSecurityGroup",
                  "ec2:DeleteVolume",
                  "ec2:DetachVolume",
                  "ec2:RevokeSecurityGroupIngress",
                  "ec2:DescribeVpcs",
                  "elasticloadbalancing:AddTags",
                  "elasticloadbalancing:AttachLoadBalancerToSubnets",
                  "elasticloadbalancing:ApplySecurityGroupsToLoadBalancer",
                  "elasticloadbalancing:CreateLoadBalancer",
                  "elasticloadbalancing:CreateLoadBalancerPolicy",
                  "elasticloadbalancing:CreateLoadBalancerListeners",
                  "elasticloadbalancing:ConfigureHealthCheck",
                  "elasticloadbalancing:DeleteLoadBalancer",
                  "elasticloadbalancing:DeleteLoadBalancerListeners",
                  "elasticloadbalancing:DescribeLoadBalancers",
                  "elasticloadbalancing:DescribeLoadBalancerAttributes",
                  "elasticloadbalancing:DetachLoadBalancerFromSubnets",
                  "elasticloadbalancing:DeregisterInstancesFromLoadBalancer",
                  "elasticloadbalancing:ModifyLoadBalancerAttributes",
                  "elasticloadbalancing:RegisterInstancesWithLoadBalancer",
                  "elasticloadbalancing:SetLoadBalancerPoliciesForBackendServer",
                  "elasticloadbalancing:AddTags",
                  "elasticloadbalancing:CreateListener",
                  "elasticloadbalancing:CreateTargetGroup",
                  "elasticloadbalancing:DeleteListener",
                  "elasticloadbalancing:DeleteTargetGroup",
                  "elasticloadbalancing:DescribeListeners",
                  "elasticloadbalancing:DescribeLoadBalancerPolicies",
                  "elasticloadbalancing:DescribeTargetGroups",
                  "elasticloadbalancing:DescribeTargetHealth",
                  "elasticloadbalancing:ModifyListener",
                  "elasticloadbalancing:ModifyTargetGroup",
                  "elasticloadbalancing:RegisterTargets",
                  "elasticloadbalancing:SetLoadBalancerPoliciesOfListener",
                  "iam:CreateServiceLinkedRole",
                  "ecr:GetAuthorizationToken",
                  "ecr:BatchCheckLayerAvailability",
                  "ecr:GetDownloadUrlForLayer",
                  "ecr:GetRepositoryPolicy",
                  "ecr:DescribeRepositories",
                  "ecr:ListImages",
                  "ecr:BatchGetImage",
                  "kms:DescribeKey"
              ],
              "Resource": [
                  "*"
              ]
          }
      ]
  }
```

1. Criar a última *Policy* no IAM com o nome “**K8sWorkerProfile**”, com o seguinte JSON:

```json
{
      "Version": "2012-10-17",
      "Statement": [
          {
              "Effect": "Allow",
              "Action": [
                  "ec2:DescribeInstances",
                  "ec2:DescribeRegions",
                  "ecr:GetAuthorizationToken",
                  "ecr:BatchCheckLayerAvailability",
                  "ecr:GetDownloadUrlForLayer",
                  "ecr:GetRepositoryPolicy",
                  "ecr:DescribeRepositories",
                  "ecr:ListImages",
                  "ecr:BatchGetImage"
              ],
              "Resource": "*"
          }
      ]
  }
```

1. É necessário também que tenha um *securitygroup* com as portas do RKE liberadas. Caso tenha dificuldades, pode subir um SG aberto para acesso interno e externo. 
    
    *obs: Não é o recomendado para as boas práticas de segurança*
    

## Deploy Nodes

Uma vez que configuramos os elementos da AWS, hora de criar as instâncias na AWS.

> *Escolha uma família e tipo de instância única pois esse passo-a-passo não cobre deploys com instâncias diversas. O modelo escolhido foi c6a.xlarge, mas fique a vontade para escolher o seu*
> 
1. O *master node* é criado de forma manual, pois ele não pertence ao grupo de auto-scaling (será coberto mais a frente essa explicação). Sendo assim, crie uma instância da forma tradicional, com as seguintes modificações:
    1. AMI Name: ubuntu/images/hvm-ssd/ubuntu-bionic-18.04-amd64-server-20220610
    2. IAM Role: K8sMasterRole
    3. Security group: <O criado por você>
    4. Tags:
        
        • **`kubernetes.io/cluster/<clusterID>: owned`**
        
    5. No campo user data, nós podemos informar um script a ser realizado durante a criação da máquina. Para o master use o [K8sMasterUserData](https://www.notion.so/K8sMasterUserData-6c97ab3e7bde4f259aeb9939456e2823) informado na seção anterior
2. O *worker node* é criado através do ASG (*Auto Scale Group*). Sendo assim, a sua criação será automática assim que criarmos o ASG. Para criar o grupo, basta ir ao serviço EC2 na AWS e rolar o menu para o último elemento chamado “*Auto Scaling*”. Lá você encontrará o “*Auto Scaling Groups*” em questão.
    1. Durante a criação do ASG, será necessário criar um Launch Template.  Para o template, escolher os mesmos AMI, Security Group, e usar as seguintes labels:
        1. **`kubernetes.io/cluster/<clusterID>: owned`**
        2. **`k8s.io/cluster-autoscaler/<clusterName>: true`**
        3. **`k8s.io/cluster-autoscaler/enabled: true`**

O processo de criação se da através da interface intuitiva. Únicos pontos de atenção são:

1. IAM Role: K8sWorkerRole
2. Security group: <O criado por você>
3. Tags: 
    - **`kubernetes.io/cluster/<clusterID>: owned`**
    - **`k8s.io/cluster-autoscaler/<clusterName>: true`**
    - **`k8s.io/cluster-autoscaler/enabled: true`**
4. No campo user data, nós podemos informar um script a ser realizado durante a criação da máquina. Para o worker use o [K8sWorkerUserData](https://www.notion.so/K8sWorkerUserData-05181584ba8647be9cfff661322f8146)  informado na seção anterior.
5. Definir quantidade de instâncias:
    
    `minimum: 2`
    
    `desired: 2`
    
    `maximum: 4`
    

3. Nesse momento as máquinas serão criadas e você pode acompanhar o processo através da interface do Rancher

## Deploy do deployment *autoscaler* no master

Nessa etapa é para nós já possuirmos os nós ativos e rodando no Rancher. Caso não esteja, rever os procedimentos anterirores.

Aqui, realizaremos o deploy do *cluster-autoscaler* responsável por analisar o estado do cluster e comunicar diretamente com o ASG criado para realizar o autoscaling. 

Abra o *kubectl shell* no Rancher do cluster em questão e crie o seguinte documento abaixo:

vi **cluster-autoscaler-deployment.yaml**

```yaml
---
apiVersion: v1
kind: ServiceAccount
metadata:
  labels:
    k8s-addon: cluster-autoscaler.addons.k8s.io
    k8s-app: cluster-autoscaler
  name: cluster-autoscaler
  namespace: kube-system
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: cluster-autoscaler
  labels:
    k8s-addon: cluster-autoscaler.addons.k8s.io
    k8s-app: cluster-autoscaler
rules:
  - apiGroups: [""]
    resources: ["events", "endpoints"]
    verbs: ["create", "patch"]
  - apiGroups: [""]
    resources: ["pods/eviction"]
    verbs: ["create"]
  - apiGroups: [""]
    resources: ["pods/status"]
    verbs: ["update"]
  - apiGroups: [""]
    resources: ["endpoints"]
    resourceNames: ["cluster-autoscaler"]
    verbs: ["get", "update"]
  - apiGroups: [""]
    resources: ["nodes"]
    verbs: ["watch", "list", "get", "update"]
  - apiGroups: [""]
    resources:
      - "pods"
      - "services"
      - "replicationcontrollers"
      - "persistentvolumeclaims"
      - "persistentvolumes"
    verbs: ["watch", "list", "get"]
  - apiGroups: ["extensions"]
    resources: ["replicasets", "daemonsets"]
    verbs: ["watch", "list", "get"]
  - apiGroups: ["policy"]
    resources: ["poddisruptionbudgets"]
    verbs: ["watch", "list"]
  - apiGroups: ["apps"]
    resources: ["statefulsets", "replicasets", "daemonsets"]
    verbs: ["watch", "list", "get"]
  - apiGroups: ["storage.k8s.io"]
    resources: ["storageclasses", "csinodes"]
    verbs: ["watch", "list", "get"]
  - apiGroups: ["batch", "extensions"]
    resources: ["jobs"]
    verbs: ["get", "list", "watch", "patch"]
  - apiGroups: ["coordination.k8s.io"]
    resources: ["leases"]
    verbs: ["create"]
  - apiGroups: ["coordination.k8s.io"]
    resourceNames: ["cluster-autoscaler"]
    resources: ["leases"]
    verbs: ["get", "update"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: cluster-autoscaler
  namespace: kube-system
  labels:
    k8s-addon: cluster-autoscaler.addons.k8s.io
    k8s-app: cluster-autoscaler
rules:
  - apiGroups: [""]
    resources: ["configmaps"]
    verbs: ["create","list","watch"]
  - apiGroups: [""]
    resources: ["configmaps"]
    resourceNames: ["cluster-autoscaler-status", "cluster-autoscaler-priority-expander"]
    verbs: ["delete", "get", "update", "watch"]

---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: cluster-autoscaler
  labels:
    k8s-addon: cluster-autoscaler.addons.k8s.io
    k8s-app: cluster-autoscaler
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-autoscaler
subjects:
  - kind: ServiceAccount
    name: cluster-autoscaler
    namespace: kube-system

---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: cluster-autoscaler
  namespace: kube-system
  labels:
    k8s-addon: cluster-autoscaler.addons.k8s.io
    k8s-app: cluster-autoscaler
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: cluster-autoscaler
subjects:
  - kind: ServiceAccount
    name: cluster-autoscaler
    namespace: kube-system

---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: cluster-autoscaler
  namespace: kube-system
  labels:
    app: cluster-autoscaler
spec:
  replicas: 1
  selector:
    matchLabels:
      app: cluster-autoscaler
  template:
    metadata:
      labels:
        app: cluster-autoscaler
      annotations:
        prometheus.io/scrape: 'true'
        prometheus.io/port: '8085'
    spec:
      serviceAccountName: cluster-autoscaler
      tolerations:
        - effect: NoSchedule
          operator: "Equal"
          value: "true"
          key: node-role.kubernetes.io/controlplane
      nodeSelector:
        node-role.kubernetes.io/controlplane: "true"
      containers:
        - image: eu.gcr.io/k8s-artifacts-prod/autoscaling/cluster-autoscaler:v1.21.3
          name: cluster-autoscaler
          resources:
            limits:
              cpu: 100m
              memory: 300Mi
            requests:
              cpu: 100m
              memory: 300Mi
          command:
            - ./cluster-autoscaler
            - --v=4
            - --stderrthreshold=info
            - --cloud-provider=aws
            - --skip-nodes-with-local-storage=false
            - --expander=least-waste
						- --scale-down-enabled=true
						- --scale-down-delay-after-add=1m
            - --node-group-auto-discovery=asg:tag=k8s.io/cluster-autoscaler/enabled,k8s.io/cluster-autoscaler/cluster-autoscaler
          volumeMounts:
            - name: ssl-certs
              mountPath: /etc/ssl/certs/ca-certificates.crt
              readOnly: true
          imagePullPolicy: "Always"
      volumes:
        - name: ssl-certs
          hostPath:
            path: "/etc/ssl/certs/ca-certificates.crt"
```

## Testando

Para testar o *autoscaling*, realizaremos o deploy de uma aplicação dummy e escalaremos até obter um over-request no cluster. 

O cluster-scaler acontecerá se:

- Possuírem pods que falharam no cluster devido a recursos insuficientes (SCALE UP)

OU

- Possuem nós no cluster que não são mais necessários (SCALE DOWN)

Adapte o deploy a seguir para melhor coincidir com seu ambiente.

```json
apiVersion: apps/v1
kind: Deployment
metadata:
  labels:
    app: hello-world
  name: hello-world
spec:
  replicas: 3
  selector:
    matchLabels:
      app: hello-world
  strategy:
    rollingUpdate:
      maxSurge: 1
      maxUnavailable: 0
    type: RollingUpdate
  template:
    metadata:
      labels:
        app: hello-world
    spec:
      containers:
      - image: rancher/hello-world
        imagePullPolicy: Always
        name: hello-world
        ports:
        - containerPort: 80
          protocol: TCP
        resources:
          limits:
            cpu: 1000m
            memory: 1024Mi
          requests:
            cpu: 1000m
            memory: 1024Mi
```

---

### Erros comuns
