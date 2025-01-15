#!/bin/bash
# Find the PID of the process using port 3000
PID=$(lsof -ti :3000)
if [ -n "$PID" ]; then
  echo "Killing process on port 3000 with PID: $PID"
  kill -9 $PID
  echo "Process killed successfully."
else
  echo "No process found on port 3000."
fi
#test