#!/bin/sh

DAEMON="/usr/bin/aesdsocket"
DAEMON_OPT="-d"
PROGRAM=aesdsocket
SIGNALTERM="TERM"

case "$1" in
  start)
    echo "Starting $PROGRAM..."
    start-stop-daemon --start --name ${PROGRAM} --startas ${DAEMON} -- ${DAEMON_OPT}
    ;;
  stop)
    echo "Stopping $PROGRAM..."
    start-stop-daemon --stop --name ${PROGRAM} --signal ${SIGNALTERM}
    ;;
  *)
    echo "Usage: $0 {start|stop}"
    exit 1;
esac

