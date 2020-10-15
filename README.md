# unifi
1) Copy the link location of the script.

2) SSH into your Ubuntu/Debian machine, and login as root. ( Ubuntu | sudo -i | Debian | su )

3) Make sure the ca-certificates package is installed.

```bash
apt-get update; apt-get install ca-certificates wget -y
```
4) Install the latest and greatest UniFi Network Controller with 1 line. ( copy paste )

```bash
cd /var/tmp/
rm unifi-latest.sh &> /dev/null; wget https://raw.githubusercontent.com/talgan/unifi/main/unifi-latest.sh && bash unifi-latest.sh
```
5) Once the installation is completed browse to your controller.

```bash
https://ip.of.your.server:8443
```

source:
https://community.ui.com/questions/UniFi-Installation-Scripts-or-UniFi-Easy-Update-Script-or-UniFi-Lets-Encrypt-or-Ubuntu-16-04-18-04-/ccbc7530-dd61-40a7-82ec-22b17f027776?page=10
