#!/bin/bash

# Check if at least one argument was provided
if [ $# -eq 0 ]; then
  echo "Usage: $0 command [args...]"
  echo "Example: $0 python my_script.py"
  exit 1
fi

WIRESHARK_BIN="/Applications/Wireshark.app/Contents/MacOS/Wireshark"
SSLKEYLOGFILE="keylog.txt"
OUTPUT_FILE="tcpdump.pcap"

# Start tcpdump in background with -U flag for unbuffered output
echo "Starting tcpdump capture on localhost port 4433..."
tcpdump -i lo0 port 4433 -U -w "$OUTPUT_FILE" &
TCPDUMP_PID=$!

# Wait a moment to ensure tcpdump starts
sleep 1

# Execute the command provided as arguments
echo "Running command: $@"
"$@"
CMD_EXIT_CODE=$?

# Stop tcpdump
echo "Stopping tcpdump..."
sleep 1
kill -TERM $TCPDUMP_PID
wait $TCPDUMP_PID 2>/dev/null

echo "Capture saved to $OUTPUT_FILE"
echo "Command exited with code $CMD_EXIT_CODE"

# Open the pcap file with Wireshark directly
echo "Opening capture in Wireshark..."
echo "$WIRESHARK_BIN" -o "tls.keylog_file:$SSLKEYLOGFILE" "$OUTPUT_FILE"
"$WIRESHARK_BIN" -o "tls.keylog_file:$SSLKEYLOGFILE" "$OUTPUT_FILE" &

exit $CMD_EXIT_CODE
