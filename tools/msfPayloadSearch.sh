#!/bin/bash

if [ $# -eq 0 ]
  then
    echo "[*] Usage: msfPayloadSearch.sh <keyword>"
    echo "[*] This script is for searching available payloads for command msfvenom. It is just a command wrapper."
    exit
fi


cmd="msfvenom -l payloads "
for i in "$@"
do
    cmd=$(echo $cmd && echo "|grep $i ")
done
eval $cmd