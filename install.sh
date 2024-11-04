#!/bin/bash

# Date: 03/11/2024
# Author: Ricardo Vega
# This script download ans install
# python3 and pip3 if necessary

echo "Hi ${USER} !!!"

if ! command -v python3 &>/dev/null || ! command -v pip3 &>/dev/null; then
    read -p "Quieres instalar python3 y pip3? Y/n: " sn
    if [[ "${sn}" == "y" || "${sn}" == "Y" ]]; then
        apt-get install -y python3
        apt-get install -y python3-pip
    fi
fi
