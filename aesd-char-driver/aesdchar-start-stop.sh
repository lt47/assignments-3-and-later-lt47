case "$1" in
    start)
        echo "Loading AESD char driver"
        /lib/modules/$(uname -r)/extra/aesdchar_load
     ;;
    stop)

        echo "Unloading AESD char driver"
        /lib/modules/$(uname -r)/extra/aesdchar_unload

    ;;
    *)
        echo "Usage: $0 {start|stop}"
        exit 1
esac
