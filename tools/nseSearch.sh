#!/bin/bash

if [ $# -eq 0 ]
  then
    echo "[*] Usage: nseSearch.sh <keyword>"
    echo "[*] This tool is for searching NMap script files. It is just a small command wrapper but saves you time for searching useful nmap scripts under `/usr/share/nmap/scripts/` folder."
    exit
fi

ls -la /usr/share/nmap/scripts/ |grep $1 |awk -F ' ' '{print $NF}'