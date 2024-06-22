#!/bin/bash

NAME="kubntu-setup"
VERSION="1.29.4"
POD_NETWORK_CIDR="10.79.0.0/16"
SVC_NETWORK_CIDR="10.80.0.0/12"
CLUSTER_NAME="kubntu"
EMAIL="john.doe@inter.net"
BUILD_START=$(date +%s)
SUPRESS_OUTPUT="2>&1>/dev/null"
SUPRESS_STDOUT="1>/dev/null"
SUPRESS_STDERR="2>/dev/null"

################################################################################
# install aptitude apt-transport-https gpg wget
apt install -y aptitude apt-transport-https gpg wget

################################################################################
# add kubernetes community package repository and import gpg key
tee /etc/apt/sources.list.d/kubernetes.list <<EOL_KUBERNETES_REPO
deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v1.29/deb/ /
EOL_KUBERNETES_REPO

wget https://pkgs.k8s.io/core:/stable:/v1.29/deb/Release.key -O - | gpg --batch --yes --dearmor --output /etc/apt/keyrings/kubernetes-apt-keyring.gpg

apt update

################################################################################
# install containerd
apt install -y containerd

# configure containerd
mkdir -p /etc/containerd
containerd config default | tee /etc/containerd/config.toml

# fix config pause container (use same version as kubernetes)
sed -i 's/pause:3../pause:3.9/' /etc/containerd/config.toml

# fix systemd cgroup (use cgroup v2)
sed -i 's/SystemdCgroup = false/SystemdCgroup = true/' /etc/containerd/config.toml

systemctl restart containerd
if [ $? != 0 ] ; then
  echo "No systemd, I think we are on WSL -> start containerd as background process ..."
  containerd &
fi

################################################################################
# install helm
which helm
if [ $? != 0 ] ; then
  wget https://get.helm.sh/helm-v3.14.4-linux-amd64.tar.gz -O - | tar Cxzf /tmp - && cp /tmp/linux-amd64/helm /usr/local/bin/
fi

################################################################################
# install yq
which yq
if [ $? != 0 ] ; then
  wget https://github.com/mikefarah/yq/releases/download/v4.43.1/yq_linux_amd64 -O /usr/local/bin/yq && chmod +x /usr/local/bin/yq
fi

################################################################################
# deb packages for airgap installation -> https://packages.debian.org
# installed packages -> dpkg -l | sed '/^ii/!d' | tr -s ' ' | cut -d ' ' -f 2,3,4
readarray -t PACKAGES <<EOL_PACKAGES
# iptables
iptables 1.8.10-3ubuntu2 amd64
libip4tc2:amd64 1.8.10-3ubuntu2 amd64
libip6tc2:amd64 1.8.10-3ubuntu2 amd64
libjansson4:amd64 2.14-2build2 amd64
libnetfilter-conntrack3:amd64 1.0.9-6build1 amd64
libnfnetlink0:amd64 1.0.2-2build1 amd64
libnftables1:amd64 1.0.9-1build1 amd64
libnftnl11:amd64 1.2.6-2build1 amd64
# ebtables 
ebtables 2.0.11-6build1 amd64
# jq
jq 1.7.1-3build1 amd64
libjq1:amd64 1.7.1-3build1 amd64
libonig5:amd64 6.9.9-1build1 amd64
# curl
# ethtool
ethtool 1:6.7-1build1 amd64
# socat
socat 1.8.0.0-4build3 amd64
# conntrack
conntrack 1:1.4.8-1ubuntu1 amd64
# cri-tools
cri-tools 1.29.0-1.1 amd64
# kubernetes
kubeadm 1.29.6-1.1 amd64
kubectl 1.29.6-1.1 amd64
kubelet 1.29.6-1.1 amd64
kubernetes-cni 1.3.0-1.1 amd64
# containerd
containerd 1.7.12-0ubuntu4 amd64
runc 1.1.12-0ubuntu3 amd64
# wireguard
wireguard 1.0.20210914-1ubuntu4 all
wireguard-tools 1.0.20210914-1ubuntu4 amd64
EOL_PACKAGES

mkdir -p deb

aptitude clean

for PACKAGE in "${PACKAGES[@]}" ; do
  # don't process commented out packages
  [ ${PACKAGE:0:1} = \# ] && continue

  # parse package data
  PACKAGE_DATA=($PACKAGE)
  PACKAGE_NAME="${PACKAGE_DATA[0]%:amd64}"
  PACKAGE_VERSION="${PACKAGE_DATA[1]}"
  PACKAGE_ARCH="${PACKAGE_DATA[2]}"
  PACKAGE_VERSION_FILE=$(echo $PACKAGE_VERSION |sed 's/:/%3a/')
  PACKAGE_FILE="${PACKAGE_NAME}_${PACKAGE_VERSION_FILE}_${PACKAGE_ARCH}.deb"

  # skip download if already available
  [ -f deb/$PACKAGE_FILE ] && continue

  # download package
  aptitude --download-only install -y $PACKAGE_NAME=$PACKAGE_VERSION
  cp /var/cache/apt/archives/$PACKAGE_FILE deb/
  if [ $? != 0 ] ; then
    # aptitude will not download if package is installed, try download reinstall
    aptitude --download-only reinstall $PACKAGE_NAME
    cp /var/cache/apt/archives/$PACKAGE_FILE deb/
    [ $? != 0 ] && exit 1
  fi 
done

################################################################################
# download gum package -> https://github.com/charmbracelet/gum
wget https://github.com/charmbracelet/gum/releases/download/v0.14.0/gum_0.14.0_amd64.deb -P deb

################################################################################
# container images for airgap installation
# ctr -n k8s.io images list -q
readarray -t IMAGES <<EOL_IMAGES
################################################################################
# openebs 3.9.0 -> https://artifacthub.io/packages/helm/openebs/openebs/3.9.0
docker.io/openebs/node-disk-manager:2.1.0
docker.io/openebs/provisioner-localpv:3.4.0
docker.io/openebs/node-disk-operator:2.1.0
docker.io/openebs/node-disk-exporter:2.1.0
docker.io/openebs/linux-utils:3.4.0
################################################################################
# cert-manager 1.14.5 -> https://artifacthub.io/packages/helm/cert-manager/cert-manager/1.14.5
quay.io/jetstack/cert-manager-cainjector:v1.14.5
quay.io/jetstack/cert-manager-controller:v1.14.5
quay.io/jetstack/cert-manager-webhook:v1.14.5
quay.io/jetstack/cert-manager-acmesolver:v1.14.5
quay.io/jetstack/cert-manager-ctl:v1.14.5
quay.io/jetstack/cert-manager-webhook:v1.14.5
################################################################################
# ingress-nginx v1.10.1 -> https://github.com/kubernetes/ingress-nginx/blob/helm-chart-4.10.1/charts/ingress-nginx/values.yaml#L29
registry.k8s.io/ingress-nginx/controller:v1.10.1
registry.k8s.io/ingress-nginx/opentelemetry:v20230721-3e2062ee5
registry.k8s.io/ingress-nginx/kube-webhook-certgen:v1.4.1
registry.k8s.io/defaultbackend-amd64:1.5
################################################################################
# metrics-server v0.7.1 -> https://artifacthub.io/packages/helm/metrics-server/metrics-server/3.12.1
registry.k8s.io/metrics-server/metrics-server:v0.7.1
################################################################################
# calico v3.27.3 -> https://artifacthub.io/packages/helm/projectcalico/tigera-operator/3.27.3
quay.io/tigera/operator:v1.32.7
docker.io/calico/apiserver:v3.27.3
docker.io/calico/cni:v3.27.3
docker.io/calico/csi:v3.27.3
docker.io/calico/kube-controllers:v3.27.3
docker.io/calico/node-driver-registrar:v3.27.3
docker.io/calico/node:v3.27.3
docker.io/calico/pod2daemon-flexvol:v3.27.3
docker.io/calico/typha:v3.27.3
################################################################################
# k8s 1.29.4 -> https://github.com/kubernetes/kubernetes/blob/master/CHANGELOG/CHANGELOG-1.29.md#container-images
registry.k8s.io/kube-apiserver:v1.29.4
registry.k8s.io/kube-controller-manager:v1.29.4
registry.k8s.io/kube-proxy:v1.29.4
registry.k8s.io/kube-scheduler:v1.29.4
registry.k8s.io/coredns/coredns:v1.11.1
registry.k8s.io/etcd:3.5.12-0
registry.k8s.io/pause:3.9
################################################################################
# velero -> https://github.com/vmware-tanzu/velero
docker.io/velero/velero:v1.13.2
docker.io/velero/velero-plugin-for-aws:v1.9.2
EOL_IMAGES

CONTAINER_IMAGES=""

for IMAGE in "${IMAGES[@]}" ; do
  # don't process commented out images
  [ ${IMAGE:0:1} = \# ] && continue

  ctr image pull $IMAGE

  # exit on pull error
  [ $? != 0 ] && echo "ERROR: can't pull image" && exit 1

  CONTAINER_IMAGES+=" "
  CONTAINER_IMAGES+=$IMAGE
done

# create folder for container images
mkdir -p container

# cleanup container images tar file
[ -f container/images.tar ] && rm -f container/images.tar

# export all container images to images.tar 
echo "Be patient exporting container images ..."
ctr images export container/images.tar $CONTAINER_IMAGES

################################################################################
# helm charts -> chart_url chart_repo chart_name chart_version
readarray -t HELM_CHARTS <<EOL_HELM_CHARTS
https://openebs.github.io/charts openebs openebs 3.9.0
https://charts.jetstack.io jetstack cert-manager v1.14.5
https://kubernetes.github.io/ingress-nginx ingress-nginx ingress-nginx 4.10.1
https://projectcalico.docs.tigera.io/charts projectcalico tigera-operator v3.27.3
https://kubernetes-sigs.github.io/metrics-server metrics-server metrics-server 3.12.1
EOL_HELM_CHARTS

mkdir -p helm

for CHART in "${HELM_CHARTS[@]}" ; do
  # don't process commented out helm charts
  [ ${CHART:0:1} = \# ] && continue

  # parse chart data
  CHART_DATA=($CHART)
  CHART_URL="${CHART_DATA[0]}"
  CHART_REPO="${CHART_DATA[1]}"
  CHART_NAME="${CHART_DATA[2]}"
  CHART_VERSION="${CHART_DATA[3]}"

  # continue if helmchart exists
  [ -f helm/$CHART_NAME-$CHART_VERSION.tgz ] && continue

  # add helm repo
  helm repo add $CHART_REPO $CHART_URL 

  # pull helm chart
  helm pull $CHART_REPO/$CHART_NAME --version $CHART_VERSION --destination helm/

  # exit on pull error
  [ $? != 0 ] && echo "ERROR: can't pull helm chart" && exit 1
done

################################################################################
# additional artefacts
mkdir -p artefact

# download helm v3.14.4 -> https://github.com/helm/helm/releases/tag/v3.14.4
if [ -f artefact/helm-v3.14.4-linux-amd64.tar.gz ] ; then
  echo "file exists artefact/helm-v3.14.4-linux-amd64.tar.gz" 
else
  wget https://get.helm.sh/helm-v3.14.4-linux-amd64.tar.gz -P artefact
fi

# download k9s v0.32.4 -> https://github.com/derailed/k9s/releases/tag/v0.32.4
if [ -f artefact/k9s_Linux_amd64.tar.gz ] ; then
  echo "file exists artefact/k9s_Linux_amd64.tar.gz" 
else
  wget https://github.com/derailed/k9s/releases/download/v0.32.4/k9s_Linux_amd64.tar.gz -P artefact
fi

# download velero -> https://github.com/vmware-tanzu/velero/releases/tag/v1.13.2
if [ -f artefact/velero-v1.13.2-linux-amd64.tar.gz ] ; then
  echo "file exists artefact/velero-v1.13.2-linux-amd64.tar.gz" 
else
  wget https://github.com/vmware-tanzu/velero/releases/download/v1.13.2/velero-v1.13.2-linux-amd64.tar.gz -P artefact
fi

# download calico cni-plugin v3.20.6 -> https://github.com/projectcalico/cni-plugin/releases/
if [ -f artefact/calico ] ; then
  echo "file exists artefact/calico" 
else
  wget https://github.com/projectcalico/cni-plugin/releases/download/v3.20.6/calico-amd64 -O artefact/calico
fi

# download yq -> https://github.com/mikefarah/yq/releases
if [ -f artefact/yq ] ; then
  echo "file exists artefact/yq" 
else
  wget https://github.com/mikefarah/yq/releases/download/v4.43.1/yq_linux_amd64 -O artefact/yq
fi

# issuer for cert-manager (letsencrypt) -> issuer-letsencrypt.yaml
tee artefact/issuer-letsencrypt.yaml <<EOL_ISSUER
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-staging
  namespace: cert-manager
spec:
  acme:
    server: https://acme-staging-v02.api.letsencrypt.org/directory
    email: $EMAIL
    privateKeySecretRef:
      name: letsencrypt-staging
    solvers:
      - http01:
          ingress:
            class: nginx
---
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-prod
  namespace: cert-manager
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    email: $EMAIL
    privateKeySecretRef:
      name: letsencrypt-prod
    solvers:
    - http01:
       ingress:
         class: nginx
EOL_ISSUER

# kubeadm-config.yaml -> https://kubernetes.io/docs/reference/config-api/kubeadm-config.v1beta3/
tee artefact/kubeadm-config.yaml <<EOL_KUBEADM_CONFIG
kind: KubeletConfiguration
apiVersion: kubelet.config.k8s.io/v1beta1
cgroupDriver: systemd
---
kind: ClusterConfiguration
apiVersion: kubeadm.k8s.io/v1beta3
clusterName: $CLUSTER_NAME
kubernetesVersion: $VERSION
networking:
  serviceSubnet: $SVC_NETWORK_CIDR
  podSubnet: $POD_NETWORK_CIDR
controllerManager:
  extraArgs:
    bind-address: "0.0.0.0"
scheduler:
  extraArgs:
    bind-address: "0.0.0.0"
etcd:
  local:
    extraArgs:
      listen-metrics-urls: "http://0.0.0.0:2381"
EOL_KUBEADM_CONFIG

################################################################################
# create setup.sh
tee setup.sh <<EOL_SETUP
#!/bin/bash

SETUP_START=\$(date +%s)

################################################################################
# install gum (silent ;-)
dpkg --install deb/gum_0.14.0_amd64.deb $SUPRESS_OUTPUT

################################################################################
# install packages
PACKAGES=\$(find deb -name "*.deb")

gum spin --title "Install packages ..." -- dpkg --install \$PACKAGES

BETWEEN=\$(date +%s)
BETWEEN_MINUTES=\$(((\$BETWEEN - \$SETUP_START) / 60))
BETWEEN_SECONDS=\$((\$BETWEEN - \$SETUP_START - (\$BETWEEN_MINUTES * 60)))

printf "Install packages (%02d:%02d)\n" \$BETWEEN_MINUTES \$BETWEEN_SECONDS

################################################################################
# specific setup routines: init, join, upgrade or delete
if [ -z "\$1" ] ; then
  gum style \
    --foreground 212 --border-foreground 212 --border rounded \
    --align center --margin "1 1" --padding "1 1" \
    'kubntu $VERSION setup' 'select setup routine?'
  ARG1=\$(gum choose "init" "join" "upgrade" "delete")
else
  ARG1="\$1"
fi

echo "Setup routine \$ARG1"

INIT=false
JOIN=false
UPGRADE=false
DELETE=false

[ "\$ARG1" = init ] && INIT=true
[ "\$ARG1" = join ] && JOIN=true
[ "\$ARG1" = upgrade ] && UPGRADE=true
[ "\$ARG1" = delete ] && DELETE=true

if [ -z "\$2" ] ; then
  # init arguments: single or cluster
  if [ \$INIT = true ] ; then
    gum style \
      --foreground 212 --border-foreground 212 --border rounded \
      --align center --margin "1 1" --padding "1 1" \
      'initialize kubernetes' 'select single node or cluster?'
    ARG2=\$(gum choose "single" "cluster")
  fi

  # join arguments: worker or controlplane and primary controlplane ip
  if [ \$JOIN = true ] ; then
    gum style \
      --foreground 212 --border-foreground 212 --border rounded \
      --align center --margin "1 1" --padding "1 1" \
      'join node' 'select worker or controlplane?'
    ARG2=\$(gum choose "worker" "controlplane")
    ARG3=\$(gum input --placeholder "ip of primary control plane")
  fi
else
  ARG2="\$2"
  ARG3="\$3"
fi

echo "Setup task \$ARG1 \$ARG2 \$ARG3"

CLUSTER=false
SINGLE=false
CONTROLPLANE=false
WORKER=false

[ "\$ARG2" = cluster ] && CLUSTER=true
[ "\$ARG2" = single ] && SINGLE=true
[ "\$ARG2" = controlplane ] && CONTROLPLANE=true
[ "\$ARG2" = worker ] && WORKER=true

################################################################################
# add kernel module for networking and disk stuff
tee /etc/modules-load.d/k8s.conf <<EOL_MODULES $SUPRESS_OUTPUT
overlay
br_netfilter
iscsi_tcp
nvme-tcp
EOL_MODULES

modprobe --all overlay br_netfilter iscsi_tcp nvme-tcp $SUPRESS_OUTPUT

tee /etc/sysctl.d/kubernetes.conf <<EOL_SYSCTL $SUPRESS_OUTPUT
net.bridge.bridge-nf-call-ip6tables = 1
net.bridge.bridge-nf-call-iptables = 1
net.ipv4.ip_forward = 1
vm.nr_hugepages = 1024
EOL_SYSCTL

sysctl --system $SUPRESS_OUTPUT

################################################################################
# disable swap
sed -e "/swap/ s/^/#/" -i /etc/fstab $SUPRESS_OUTPUT
swapoff --all $SUPRESS_OUTPUT

# prevent swap from being re-enabled via systemd
systemctl mask swap.target $SUPRESS_STDERR

################################################################################
# enable iscsid service
systemctl enable --now iscsid $SUPRESS_STDERR

################################################################################
# containerd config
mkdir -p /etc/containerd
containerd config default | tee /etc/containerd/config.toml $SUPRESS_OUTPUT

# fix config pause container (use same version as kubernetes)
sed -i 's/pause:3../pause:3.9/' /etc/containerd/config.toml $SUPRESS_OUTPUT

# fix systemd cgroup (use cgroup v2)
sed -i 's/SystemdCgroup = false/SystemdCgroup = true/' /etc/containerd/config.toml $SUPRESS_OUTPUT

systemctl restart containerd $SUPRESS_OUTPUT

################################################################################
# install helm
tar Cxzf /tmp artefact/helm-v3.14.4-linux-amd64.tar.gz $SUPRESS_STDERR && cp /tmp/linux-amd64/helm /usr/local/bin/

################################################################################
# install k9s
tar Cxzf /tmp artefact/k9s_Linux_amd64.tar.gz $SUPRESS_STDERR && cp /tmp/k9s /usr/local/bin/

################################################################################
# install velero
tar Cxzf /tmp artefact/velero-v1.13.2-linux-amd64.tar.gz $SUPRESS_STDERR && cp /tmp/velero-v1.13.2-linux-amd64/velero /usr/local/bin/

################################################################################
# install yq
cp artefact/yq /usr/local/bin/yq && chmod 755 /usr/local/bin/yq

################################################################################
# install calico cni-plugins
cp artefact/calico /opt/cni/bin/ && chmod 755 /opt/cni/bin/calico
cp artefact/calico /opt/cni/bin/calico-ipam && chmod 755 /opt/cni/bin/calico-ipam

################################################################################
# enable kubelet services
systemctl enable kubelet

################################################################################
# import container images
gum spin --title "Import container images ..." -- ctr --namespace k8s.io images import container/images.tar

BETWEEN=\$(date +%s)
BETWEEN_MINUTES=\$(((\$BETWEEN - \$SETUP_START) / 60))
BETWEEN_SECONDS=\$((\$BETWEEN - \$SETUP_START - (\$BETWEEN_MINUTES * 60)))

printf "Import container images (%02d:%02d)\n" \$BETWEEN_MINUTES \$BETWEEN_SECONDS

################################################################################
# init kubernetes cluster -> primary control plane
if [ \$INIT = true ] ; then
  ################################################################################
  # init cluster
  NETWORK_INTERFACE=\$(ip route | grep default | awk '{print \$5}')
  IP_ADDRESS=\$(ip -brief address show \$NETWORK_INTERFACE | awk '{print \$3}' | awk -F/ '{print \$1}')
  echo "controlPlaneEndpoint: \$IP_ADDRESS" >> artefact/kubeadm-config.yaml

  gum spin --title "Init kubernetes cluster ..." -- kubeadm init --upload-certs --node-name=\$HOSTNAME --config artefact/kubeadm-config.yaml
  [ \$? != 0 ] && echo "ERROR: can't initialize cluster" && exit 1

  BETWEEN=\$(date +%s)
  BETWEEN_MINUTES=\$(((\$BETWEEN - \$SETUP_START) / 60))
  BETWEEN_SECONDS=\$((\$BETWEEN - \$SETUP_START - (\$BETWEEN_MINUTES * 60)))

  printf "Init kubernetes cluster (%02d:%02d)\n" \$BETWEEN_MINUTES \$BETWEEN_SECONDS

  ################################################################################
  # copy kube config
  mkdir ~/.kube
  ln -s /etc/kubernetes/admin.conf ~/.kube/config
fi

################################################################################
# cluster settings -> install cni calico 
if [ \$CLUSTER = true ] ; then
  ################################################################################
  # install projectcalico tigera-operator v3.27.3
  gum spin --title "Install helm tigera-operator ..." -- helm upgrade --install tigera-operator helm/tigera-operator-v3.27.3.tgz \
    --create-namespace \
    --namespace tigera-operator \
    --version v3.27.3
  if [ \$? != 0 ] ; then
    # give grace period of 2 minutes to get node ready
    kubectl wait --timeout=2m --for=condition=Ready node/\$HOSTNAME
    [ \$? != 0 ] && echo "ERROR: can't initialize cluster" && exit 1
  fi

  BETWEEN=\$(date +%s)
  BETWEEN_MINUTES=\$(((\$BETWEEN - \$SETUP_START) / 60))
  BETWEEN_SECONDS=\$((\$BETWEEN - \$SETUP_START - (\$BETWEEN_MINUTES * 60)))

  printf "Install helm tigera-operator (%02d:%02d)\n" \$BETWEEN_MINUTES \$BETWEEN_SECONDS
fi

################################################################################
# single node cluster
if [ \$SINGLE = true ] ; then
  ################################################################################
  # remove no schedule taint for control plane
  kubectl taint nodes \$HOSTNAME node-role.kubernetes.io/control-plane=:NoSchedule- $SUPRESS_OUTPUT

  ################################################################################
  # install projectcalico tigera-operator v3.27.3
  gum spin --title "Install helm tigera-operator ..." -- helm upgrade --install tigera-operator helm/tigera-operator-v3.27.3.tgz \
    --create-namespace \
    --namespace tigera-operator \
    --version v3.27.3
  if [ \$? != 0 ] ; then
    # give grace period of 2 minutes to get node ready
    kubectl wait --timeout=2m --for=condition=Ready node/\$HOSTNAME
    [ \$? != 0 ] && echo "ERROR: can't initialize cluster" && exit 1
  fi

  BETWEEN=\$(date +%s)
  BETWEEN_MINUTES=\$(((\$BETWEEN - \$SETUP_START) / 60))
  BETWEEN_SECONDS=\$((\$BETWEEN - \$SETUP_START - (\$BETWEEN_MINUTES * 60)))

  printf "Install helm tigera-operator (%02d:%02d)\n" \$BETWEEN_MINUTES \$BETWEEN_SECONDS

  ################################################################################
  # install openebs openebs 3.9.0
  gum spin --title "Install helm openebs ..." -- helm upgrade --install openebs helm/openebs-3.9.0.tgz \
    --create-namespace \
    --namespace openebs \
    --version 3.9.0
  
  BETWEEN=\$(date +%s)
  BETWEEN_MINUTES=\$(((\$BETWEEN - \$SETUP_START) / 60))
  BETWEEN_SECONDS=\$((\$BETWEEN - \$SETUP_START - (\$BETWEEN_MINUTES * 60)))

  printf "Install helm openebs (%02d:%02d)\n" \$BETWEEN_MINUTES \$BETWEEN_SECONDS

  # set default storage class
  kubectl patch storageclass openebs-hostpath -p '{"metadata": {"annotations":{"storageclass.kubernetes.io/is-default-class":"true"}}}' $SUPRESS_OUTPUT

  ################################################################################
  # install ingress-nginx controller
  gum spin --title "Install helm ingress-nginx ..." -- helm upgrade --install ingress-nginx helm/ingress-nginx-4.10.1.tgz \
    --create-namespace \
    --namespace ingress-nginx \
    --version 4.10.1 \
    --set controller.service.type=NodePort \
    --set controller.service.nodePorts.http=30080 \
    --set controller.service.nodePorts.https=30443

  BETWEEN=\$(date +%s)
  BETWEEN_MINUTES=\$(((\$BETWEEN - \$SETUP_START) / 60))
  BETWEEN_SECONDS=\$((\$BETWEEN - \$SETUP_START - (\$BETWEEN_MINUTES * 60)))

  printf "Install helm ingress-nginx (%02d:%02d)\n" \$BETWEEN_MINUTES \$BETWEEN_SECONDS

  ################################################################################
  # install cert-manager
  gum spin --title "Install helm cert-manager ..." -- helm upgrade --install cert-manager helm/cert-manager-v1.14.5.tgz \
    --create-namespace \
    --namespace cert-manager \
    --version v1.14.5 \
    --set installCRDs=true

  kubectl apply -f artefact/issuer-letsencrypt.yaml $SUPRESS_OUTPUT

  BETWEEN=\$(date +%s)
  BETWEEN_MINUTES=\$(((\$BETWEEN - \$SETUP_START) / 60))
  BETWEEN_SECONDS=\$((\$BETWEEN - \$SETUP_START - (\$BETWEEN_MINUTES * 60)))

  printf "Install helm cert-manager (%02d:%02d)\n" \$BETWEEN_MINUTES \$BETWEEN_SECONDS

  ################################################################################
  # install metrics-server 3.12.1
  gum spin --title "Install helm metrics-server ..." -- helm upgrade --install metrics-server helm/metrics-server-3.12.1.tgz \
    --create-namespace \
    --namespace monitoring \
    --version 3.12.1 \
    --set args="{--kubelet-insecure-tls}"

  BETWEEN=\$(date +%s)
  BETWEEN_MINUTES=\$(((\$BETWEEN - \$SETUP_START) / 60))
  BETWEEN_SECONDS=\$((\$BETWEEN - \$SETUP_START - (\$BETWEEN_MINUTES * 60)))

  printf "Install helm metrics-server (%02d:%02d)\n" \$BETWEEN_MINUTES \$BETWEEN_SECONDS

  # patch metrics bind address in configmap kube-proxy
  kubectl get configmap kube-proxy --namespace kube-system -o yaml | \
  sed 's/metricsBindAddress: ""/metricsBindAddress: "0.0.0.0"/' | \
  kubectl apply -f - $SUPRESS_STDERR $SUPRESS_STDOUT

  kubectl delete pod --selector k8s-app=kube-proxy --namespace kube-system $SUPRESS_OUTPUT
fi

################################################################################
# join worker
if [ \$JOIN = true ] && [ \$WORKER = true ] ; then
  ssh -oBatchMode=yes -q \$ARG3 exit
  if [ \$? = 0 ] ; then
    mkdir -p ~/.kube
    scp \$ARG3:~/.kube/config ~/.kube/config
    JOIN_WORKER=\$(ssh -oBatchMode=yes \$ARG3 kubeadm token create --print-join-command)
    eval \$JOIN_WORKER
  else
    echo "ERROR: can't connect to \$ARG3 via ssh"
    exit 1
  fi

  ################################################################################
  # install openebs openebs 3.9.0 (mayastor)
  gum spin --title "Install helm openebs (mayastor) ..." -- helm upgrade --install openebs helm/openebs-3.9.0.tgz \
    --create-namespace \
    --namespace openebs \
    --set mayastor.enabled=true \
    --set mayastor.etcd.replicaCount=1 \
    --set mayastor.etcd.persistence.storageClass=mayastor-etcd-localpv \
    --reuse-values \
    --version 3.9.0
  
  BETWEEN=\$(date +%s)
  BETWEEN_MINUTES=\$(((\$BETWEEN - \$SETUP_START) / 60))
  BETWEEN_SECONDS=\$((\$BETWEEN - \$SETUP_START - (\$BETWEEN_MINUTES * 60)))

  printf "Install helm openebs (mayastor) (%02d:%02d)\n" \$BETWEEN_MINUTES \$BETWEEN_SECONDS

  # label node for mayastor usage
  kubectl label node \$HOSTNAME openebs.io/engine=mayastor $SUPRESS_OUTPUT

  # set default storage class
  kubectl patch storageclass openebs-single-replica -p '{"metadata": {"annotations":{"storageclass.kubernetes.io/is-default-class":"true"}}}' $SUPRESS_OUTPUT

  ################################################################################
  # install ingress-nginx controller
  gum spin --title "Install helm ingress-nginx ..." -- helm upgrade --install ingress-nginx helm/ingress-nginx-4.10.1.tgz \
    --create-namespace \
    --namespace ingress-nginx \
    --version 4.10.1 \
    --set controller.service.type=NodePort \
    --set controller.service.nodePorts.http=30080 \
    --set controller.service.nodePorts.https=30443

  BETWEEN=\$(date +%s)
  BETWEEN_MINUTES=\$(((\$BETWEEN - \$SETUP_START) / 60))
  BETWEEN_SECONDS=\$((\$BETWEEN - \$SETUP_START - (\$BETWEEN_MINUTES * 60)))

  printf "Install helm ingress-nginx (%02d:%02d)\n" \$BETWEEN_MINUTES \$BETWEEN_SECONDS

  ################################################################################
  # install cert-manager
  gum spin --title "Install helm cert-manager ..." -- helm upgrade --install cert-manager helm/cert-manager-v1.14.5.tgz \
    --create-namespace \
    --namespace cert-manager \
    --version v1.14.5 \
    --set installCRDs=true
  
  BETWEEN=\$(date +%s)
  BETWEEN_MINUTES=\$(((\$BETWEEN - \$SETUP_START) / 60))
  BETWEEN_SECONDS=\$((\$BETWEEN - \$SETUP_START - (\$BETWEEN_MINUTES * 60)))

  printf "Install helm cert-manager (%02d:%02d)\n" \$BETWEEN_MINUTES \$BETWEEN_SECONDS

  kubectl apply -f artefact/issuer-letsencrypt.yaml $SUPRESS_OUTPUT

  ################################################################################
  # install metrics-server 3.12.1
  gum spin --title "Install helm metrics-server ..." -- helm upgrade --install metrics-server helm/metrics-server-3.12.1.tgz \
    --create-namespace \
    --namespace monitoring \
    --version 3.12.1 \
    --set args="{--kubelet-insecure-tls}"

  BETWEEN=\$(date +%s)
  BETWEEN_MINUTES=\$(((\$BETWEEN - \$SETUP_START) / 60))
  BETWEEN_SECONDS=\$((\$BETWEEN - \$SETUP_START - (\$BETWEEN_MINUTES * 60)))

  printf "Install helm metrics-server (%02d:%02d)\n" \$BETWEEN_MINUTES \$BETWEEN_SECONDS
fi

################################################################################
# join controlplane
if [ \$JOIN = true ] && [ \$CONTROLPLANE = true ] ; then
  ssh -oBatchMode=yes -q \$ARG3 exit
  if [ \$? = 0 ] ; then
    mkdir -p ~/.kube
    scp \$ARG3:~/.kube/config ~/.kube/config
    CERTIFICATE_KEY=\$(ssh -oBatchMode=yes \$ARG3 kubeadm init phase upload-certs --upload-certs | tail -1)
    JOIN_CONTROLPLANE=\$(ssh -oBatchMode=yes \$ARG3 kubeadm token create --print-join-command --certificate-key \$CERTIFICATE_KEY)
    eval \$JOIN_CONTROLPLANE
  else
    echo "ERROR: can't connect to \$ARG3 via ssh"
    exit 1
  fi
fi

################################################################################
# upgrade
if [ \$UPGRADE = true ] ; then
  echo "upgrade first contol plane node"
  systemctl restart kubelet

  # give grace period of 1 minute to get node ready
  kubectl wait --timeout=1m --for=condition=Ready node/\$HOSTNAME
  [ \$? != 0 ] && echo "ERROR: can't upgrade control plane" && exit 1

  kubeadm upgrade apply $VERSION --yes

  # TODO check node to upgrade -> primary control plane, additional control plane or worker node 
  # https://kubernetes.io/docs/tasks/administer-cluster/kubeadm/kubeadm-upgrade/
fi

################################################################################
# delete
if [ \$DELETE = true ] ; then
  echo "delete node \$HOSTNAME"
  kubectl cordon node \$HOSTNAME
  kubectl drain --ignore-daemonsets \$HOSTNAME
  kubectl delete node \$HOSTNAME
  kubeadm reset --force
fi

################################################################################
# cleanup
rm -rf setup.sh deb/ container/ artefact/ helm/  

################################################################################
# finish
SETUP_END=\$(date +%s)
SETUP_MINUTES=\$(((\$SETUP_END - \$SETUP_START) / 60))
SETUP_SECONDS=\$((\$SETUP_END - \$SETUP_START - (\$SETUP_MINUTES * 60)))

echo "setup took \$SETUP_MINUTES minutes \$SETUP_SECONDS seconds"
EOL_SETUP

chmod +x setup.sh

################################################################################
# create self extracting archive
TAR_FILE="$NAME-$VERSION.tgz"
SELF_EXTRACTABLE="$TAR_FILE.self"

echo "Be patient creating self extracting archive ..."
# pack and create self extracting archive
tar -czf $TAR_FILE  setup.sh deb/ container/ artefact/ helm/

echo '#!/bin/bash' > $SELF_EXTRACTABLE
echo 'echo Extract archive ...' >> $SELF_EXTRACTABLE
echo -n 'dd bs=`head -5 $0 | wc -c` skip=1 if=$0 ' >> $SELF_EXTRACTABLE
echo -n "$SUPRESS_STDERR" >> $SELF_EXTRACTABLE
echo ' | gunzip -c | tar -x' >> $SELF_EXTRACTABLE
echo 'exec ./setup.sh $1 $2 $3' >> $SELF_EXTRACTABLE
echo '######################################################################' >> $SELF_EXTRACTABLE

cat $TAR_FILE >> $SELF_EXTRACTABLE
chmod a+x $SELF_EXTRACTABLE

################################################################################
# cleanup
rm -rf $TAR_FILE setup.sh deb/ container/ artefact/ helm/

################################################################################
# finish
BUILD_END=$(date +%s)
BUILD_MINUTES=$((($BUILD_END - $BUILD_START) / 60))
BUILD_SECONDS=$(($BUILD_END - $BUILD_START - ($BUILD_MINUTES * 60)))

echo "build $SELF_EXTRACTABLE took $BUILD_MINUTES minutes $BUILD_SECONDS seconds"
