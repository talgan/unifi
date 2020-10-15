#!/bin/bash

# UniFi Controller Updater auto installation script.
# Version  | 1.1
# Author   | Glenn Rietveld
# Email    | glennrietveld8@hotmail.nl
# Website  | https://GlennR.nl

###################################################################################################################################################################################################
#                                                                                                                                                                                                 #
#                                                                                           Color Codes                                                                                           #
#                                                                                                                                                                                                 #
###################################################################################################################################################################################################

RESET='\033[0m'
WHITE_R='\033[39m'
RED='\033[1;31m' # Light Red.
GREEN='\033[1;32m' # Light Green.

###################################################################################################################################################################################################
#                                                                                                                                                                                                 #
#                                                                                           Start Checks                                                                                          #
#                                                                                                                                                                                                 #
###################################################################################################################################################################################################

header() {
  clear
  clear
  echo -e "${GREEN}#########################################################################${RESET}\\n"
}

header_red() {
  clear
  clear
  echo -e "${RED}#########################################################################${RESET}\\n"
}

# Check for root (SUDO).
if [[ "$EUID" -ne 0 ]]; then
  clear && clear
  echo -e "${RED}#########################################################################${RESET}\\n"
  echo -e "${WHITE_R}#${RESET} The script need to be run as root...\\n\\n"
  echo -e "${WHITE_R}#${RESET} For Ubuntu based systems run the command below to login as root"
  echo -e "${GREEN}#${RESET} sudo -i\\n"
  echo -e "${WHITE_R}#${RESET} For Debian based systems run the command below to login as root"
  echo -e "${GREEN}#${RESET} su\\n\\n"
  exit 1
fi

script_logo() {
  cat << "EOF"

  _______________ ___  _________  .___                 __         .__  .__   
  \_   _____/    |   \/   _____/  |   | ____   _______/  |______  |  | |  |  
   |    __)_|    |   /\_____  \   |   |/    \ /  ___/\   __\__  \ |  | |  |  
   |        \    |  / /        \  |   |   |  \\___ \  |  |  / __ \|  |_|  |__
  /_______  /______/ /_______  /  |___|___|  /____  > |__| (____  /____/____/
          \/                 \/            \/     \/            \/           

EOF
}

help_script() {
  if [[ "${script_option_help}" == 'true' ]]; then header; script_logo; else echo -e "\\n${WHITE_R}----${RESET}\\n"; fi
  echo -e "    Easy UniFi Network Controller Install script assistance\\n"
  echo -e "
  Script usage:
  bash $0 [options]
  
  Script options:
    --skip                      Skip any kind of manual input.
    --skip-install-haveged      Skip installation of haveged.
    --add-repository            Add UniFi Repository if --skip is used.
    --custom-url [argument]     Manually provide a UniFi Network Controller download URL.
                                example:
                                --custom-url https://dl.ui.com/unifi/5.12.72/unifi_sysvinit_all.deb
    --help                      Shows this information :)\\n\\n
  Script options for Let's Encrypt:
    --v6                        Run the script in IPv6 mode instead of IPv4.
    --email [argument]          Specify what email address you want to use
                                for renewal notifications.
                                example:
                                --email glenn@glennr.nl
    --fqdn [argument]           Specify what domain name ( FQDN ) you want to use, you
                                can specify multiple domain names with : as seperator, see
                                the example below:
                                --fqdn glennr.nl:www.glennr.nl
    --server-ip [argument]      Specify the server IP address manually.
                                example:
                                --server-ip 1.1.1.1
    --retry [argument]          Retry the unattended script if it aborts for X times.
                                example:
                                --retry 5
    --external-dns              Use external DNS server to resolve the FQDN.
    --force-renew               Force renew the certificates.
    --dns-challenge             Run the script in DNS mode instead of HTTP.\\n\\n"
  exit 0
}

mkdir -p /tmp/EUS/ &> /dev/null
rm --force /tmp/EUS/script_options &> /dev/null
rm --force /tmp/EUS/le_script_options &> /dev/null
script_option_list=(-skip --skip --skip-install-haveged --custom-url --help --v6 --ipv6 --email --mail --fqdn --domain-name --server-ip --server-address --retry --external-dns --force-renew --renew --dns --dns-challenge)

while [ -n "$1" ]; do
  case "$1" in
  -skip | --skip)
       echo "--skip" &>> /tmp/EUS/script_options
       echo "--skip" &>> /tmp/EUS/le_script_options;;
  --skip-install-haveged)
       echo "--skip-install-haveged" &>> /tmp/EUS/script_options;;
  --add-repository)
       echo "--add-repository" &>> /tmp/EUS/script_options;;
  --custom-url)
       if echo "${2}" | grep -iq ".*\.deb$"; then custom_url_down_provided=true; custom_download_url="${2}"; fi
       if [[ "${custom_url_down_provided}" == 'true' ]]; then echo "--custom-url ${2}" &>> /tmp/EUS/script_options; else echo "--custom-url" &>> /tmp/EUS/script_options; fi;;
  --help)
       script_option_help=true
       help_script;;
  --v6 | --ipv6)
       echo "--v6" &>> /tmp/EUS/le_script_options;;
  --email | --mail)
       if [[ "${script_option_list[@]}" =~ "${2}" ]]; then header_red; echo -e "${WHITE_R}#${RESET} Option ${1} requires a command argument... \\n\\n"; help_script; fi
       echo -e "--email ${2}" &>> /tmp/EUS/le_script_options
       shift;;
  --fqdn | --domain-name)
       if [[ "${script_option_list[@]}" =~ "${2}" ]]; then header_red; echo -e "${WHITE_R}#${RESET} Option ${1} requires a command argument... \\n\\n"; help_script; fi
       echo -e "--fqdn ${2}" &>> /tmp/EUS/le_script_options
       fqdn_specified=true
       shift;;
  --server-ip | --server-address)
       if [[ "${script_option_list[@]}" =~ "${2}" ]]; then header_red; echo -e "${WHITE_R}#${RESET} Option ${1} requires a command argument... \\n\\n"; help_script; fi
       echo -e "--server-ip ${2}" &>> /tmp/EUS/le_script_options
       shift;;
  --retry)
       if [[ "${script_option_list[@]}" =~ "${2}" ]]; then header_red; echo -e "${WHITE_R}#${RESET} Option ${1} requires a command argument... \\n\\n"; help_script; fi
       echo -e "--retry ${2}" &>> /tmp/EUS/le_script_options
       shift;;
  --external-dns)
       echo -e "--external-dns" &>> /tmp/EUS/le_script_options;;
  --force-renew | --renew)
       echo -e "--force-renew" &>> /tmp/EUS/le_script_options;;
  --dns | --dns-challenge)
       echo -e "--dns-challenge" &>> /tmp/EUS/le_script_options;;
  esac
  shift
done

if [[ -f /tmp/EUS/script_options && -s /tmp/EUS/script_options ]]; then IFS=" " read -r -a script_options <<< "$(tr '\r\n' ' ' < /tmp/EUS/script_options)"; fi

rm --force "$0" 2> /dev/null
rm --force unifi-latest.sh* 2> /dev/null
rm --force unifi-6.0.23.sh 2> /dev/null
wget -q https://raw.githubusercontent.com/talgan/unifi/main/unifi-6.0.23.sh "${script_options[@]}"; exit 0
