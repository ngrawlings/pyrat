#!/bin/bash

# Kill all instances of simplerelay.py
ssh root@host "pkill -f simplerelay.py"

# Launch two instances of simplerelay.py
ssh root@host "screen -dmS r1 python simplerelay.py --port 44220"
ssh root@host "screen -dmS rt python simplerelay.py --port 44440"
