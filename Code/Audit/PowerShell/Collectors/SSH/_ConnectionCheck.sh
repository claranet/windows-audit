#!/bin/bash

# Echo our starter
echo '{'

# Get our original IFS and set it to \n
IFSR=$IFS
IFS='
'
# Get the main properties
for prop in `cat /etc/*[-_]release`; do
    KEY=${prop%%=*}
    VAL=$(echo ${prop#*=} | sed "s/\"//g")
    echo '"'$KEY'": "'$VAL'",'
done

# Tie off the json with the uname string and machineidentifier
SYSTEMUNAME=$(uname -a)
echo '"uname":"'$SYSTEMUNAME'","MachineIdentifier": ""}'

# Set our IFS back to what it was
IFS=$IFSR