# Packet Mirroring lab Resource Creation
1. A single VPC with 2 subnets, one for mirrored sources and one for the collector
2. 2 Web servers created with a public IP address
3. 1 Collector server (IDS) created with NO public IP for security reasons
4. CloudNAT enabled for Internet access as needed
5. All VMs created in the same region and zone, for simplicity and cost reasons

![image](https://github.com/Pruthvi360/security-cloud/assets/107435692/67fa87be-fc6a-4d4b-982a-f13dc22a0f5c)

#Run the following to create a virtual private network:
```
gcloud compute networks create dm-stamford \
--subnet-mode=custom
```
#Add a subnet to the VPC for mirrored traffic in us-east1:
```
gcloud compute networks subnets create dm-stamford-us-east1 \
--range=172.21.0.0/24 \
--network=dm-stamford \
--region=us-east1
```
# Add a subnet to the VPC for the collector in us-east1:
```
gcloud compute networks subnets create dm-stamford-us-east1-ids \
--range=172.21.1.0/24 \
--network=dm-stamford \
--region=us-east1
```
# Run the following commands to create the firewall rules:
```
gcloud compute firewall-rules create fw-dm-stamford-allow-any-web \
--direction=INGRESS \
--priority=1000 \
--network=dm-stamford \
--action=ALLOW \
--rules=tcp:80,icmp \
--source-ranges=0.0.0.0/0

gcloud compute firewall-rules create fw-dm-stamford-ids-any-any \
--direction=INGRESS \
--priority=1000 \
--network=dm-stamford \
--action=ALLOW \
--rules=all \
--source-ranges=0.0.0.0/0 \
--target-tags=ids

gcloud compute firewall-rules create fw-dm-stamford-iapproxy \
--direction=INGRESS \
--priority=1000 \
--network=dm-stamford \
--action=ALLOW \
--rules=tcp:22,icmp \
--source-ranges=35.235.240.0/20
```
# Create a Cloud Router
```
gcloud compute routers create router-stamford-nat-us-east1 \
--region=us-east1 \
--network=dm-stamford
```
# Configure a Cloud NAT
```
gcloud compute routers nats create nat-gw-dm-stamford-us-east1 \
--router=router-stamford-nat-us-east1 \
--router-region=us-east1 \
--auto-allocate-nat-external-ips \
--nat-all-subnet-ip-ranges
```
#  Create virtual machines
```
gcloud compute instance-templates create template-dm-stamford-web-us-east1 \
--region=us-east1 \
--network=dm-stamford \
--subnet=dm-stamford-us-east1 \
--machine-type=e2-small \
--image=ubuntu-1604-xenial-v20200807 \
--image-project=ubuntu-os-cloud \
--tags=webserver \
--metadata=startup-script='#! /bin/bash
  apt-get update
  apt-get install apache2 -y
  vm_hostname="$(curl -H "Metadata-Flavor:Google" \
  http://169.254.169.254/computeMetadata/v1/instance/name)"
  echo "Page served from: $vm_hostname" | \
  tee /var/www/html/index.html
  systemctl restart apache2'
```
# Create a managed instance group for the web server
```
gcloud compute instance-groups managed create mig-dm-stamford-web-us-east1 \
    --template=template-dm-stamford-web-us-east1 \
    --size=2 \
    --zone=us-east1-d
```
# Create an Instance Template for the IDS VM
```
gcloud compute instance-templates create template-dm-stamford-ids-us-east1 \
--region=us-east1 \
--network=dm-stamford \
--no-address \
--subnet=dm-stamford-us-east1-ids \
--image=ubuntu-1604-xenial-v20200807 \
--image-project=ubuntu-os-cloud \
--tags=ids,webserver \
--metadata=startup-script='#! /bin/bash
  apt-get update
  apt-get install apache2 -y
  vm_hostname="$(curl -H "Metadata-Flavor:Google" \
  http://169.254.169.254/computeMetadata/v1/instance/name)"
  echo "Page served from: $vm_hostname" | \
  tee /var/www/html/index.html
  systemctl restart apache2'
```
# Create a managed instance group for the IDS VM
```
gcloud compute instance-groups managed create mig-dm-stamford-ids-us-east1 \
    --template=template-dm-stamford-ids-us-east1 \
    --size=1 \
    --zone=us-east1-d
```
# Create an internal load balancer
# Create a basic health check for the backend services:
```
gcloud compute health-checks create tcp hc-tcp-80 --port 80
```
# Create a backend service group to be used for an ILB:
```
gcloud compute backend-services create be-dm-stamford-suricata-us-east1 \
--load-balancing-scheme=INTERNAL \
--health-checks=hc-tcp-80 \
--network=dm-stamford \
--protocol=TCP \
--region=us-east1
```
# Add the created IDS managed instance group into the backend service group created in the previous step:
```
gcloud compute backend-services add-backend be-dm-stamford-suricata-us-east1 \
--instance-group=mig-dm-stamford-ids-us-east1 \
--instance-group-zone=us-east1-d \
--region=us-east1
```
# Create a front end forwarding rule to act as the collection endpoint:
```
 gcloud compute forwarding-rules create ilb-dm-stamford-suricata-ilb-us-east1 \
 --load-balancing-scheme=INTERNAL \
 --backend-service be-dm-stamford-suricata-us-east1 \
 --is-mirroring-collector \
 --network=dm-stamford \
 --region=us-east1 \
 --subnet=dm-stamford-us-east1-ids \
 --ip-protocol=TCP \
 --ports=all
```
# Install open source IDS - Suricata
```
sudo apt-get update -y

sudo apt-get install libpcre3-dbg libpcre3-dev autoconf automake libtool libpcap-dev libnet1-dev libyaml-dev zlib1g-dev libcap-ng-dev libmagic-dev libjansson-dev libjansson4 -y

sudo apt-get install libnspr4-dev -y

sudo apt-get install libnss3-dev -y

sudo apt-get install liblz4-dev -y

sudo apt install rustc cargo -y

sudo add-apt-repository ppa:oisf/suricata-stable -y

sudo apt-get update -y

sudo apt-get install suricata -y

suricata -V
```
# Configure and review Suricata
```
sudo systemctl stop suricata

sudo cp /etc/suricata/suricata.yaml /etc/suricata/suricata.backup
```

# Download and replace new Suricata configuration file and abridged rules file
```

wget https://storage.googleapis.com/tech-academy-enablement/GCP-Packet-Mirroring-with-OpenSource-IDS/suricata.yaml

wget https://storage.googleapis.com/tech-academy-enablement/GCP-Packet-Mirroring-with-OpenSource-IDS/my.rules

sudo mkdir /etc/suricata/poc-rules

sudo cp my.rules /etc/suricata/poc-rules/my.rules

sudo cp suricata.yaml /etc/suricata/suricata.yaml

sudo systemctl start suricata
sudo systemctl restart suricata
```

# Configure Packet Mirror policy
```
gcloud compute packet-mirrorings create mirror-dm-stamford-web \
--collector-ilb=ilb-dm-stamford-suricata-ilb-us-east1 \
--network=dm-stamford \
--mirrored-subnets=dm-stamford-us-east1 \
--region=us-east1
```
# In cloud Shell
```
gcloud compute instances list
```
# Test packet mirroring
```
sudo tcpdump -i ens4 -nn -n "(icmp or port 80) and net 172.21.0.0/24"
```

# From webserver
```
sudo apt install iputils-ping
ping -c 4 [PUBLIC_IP_WEB1]
ping -c 4 [PUBLIC_IP_WEB2]
http://[PUBLIC_IP_WEB1]/
http://[PUBLIC_IP_WEB2]/
```

# TEST 1: Test egress UDP rule/alert.
```
dig @8.8.8.8 example.com
```
Run the following command in the SSH window for the IDS VM:
```
egrep "BAD UDP DNS" /var/log/suricata/eve.json
```
# TEST 2: Test egress "TCP" rule/alert
```
telnet 100.64.1.1 6667
```
# Run the following command from the SSH window of the IDS VM:
```
egrep "BAD TCP" /var/log/suricata/eve.json
```
# TEST 3: Test ingress "ICMP" rule/alert
```
ping -c 3 [PUBLIC_IP_WEB1]
```
# Now, view the alert in the Suricata event log file on the IDS VM:
```
egrep "BAD ICMP" /var/log/suricata/eve.json
```
# TEST 4: Test ingress "HTTP" rule/alert.
# Replace [PUBLIC_IP_WEB1] with the public IP address of "WEB1".
```
http://[PUBLIC_IP_WEB1]/index.php
```
# Now, view the alert in the Suricata event log file on the IDS VM:
```
egrep "BAD HTTP" /var/log/suricata/eve.json
```
