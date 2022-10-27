# lte1 iface reset based of current connection
# frequency of check: 5min intervals
#
/tool netwatch
add comment="NetWatch LTE ifupdown conditional" down-script=" /interface lte set lte1 disabled=yes\r\
    \n/delay 60s" host=8.8.8.8 interval=5m up-script="/interface lte set lte1 disabled=no"
