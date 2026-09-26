#!/bin/sh
set -eu

# All receivers are local testbed services. Synthetic UDP profiles are not
# applications such as WhatsApp or commercial VoIP/video products.
mkdir -p /srv/www
printf '%s\n' 'IPsec Sentinel testbed HTTP endpoint' >/srv/www/index.html
busybox httpd -f -p 80 -h /srv/www >/dev/null 2>&1 &
iperf3 -s >/dev/null 2>&1 &
socat -u UDP-RECVFROM:5060,reuseaddr,fork - >/dev/null 2>&1 &
socat -u UDP-RECVFROM:5004,reuseaddr,fork - >/dev/null 2>&1 &
socat -u UDP-RECVFROM:3478,reuseaddr,fork - >/dev/null 2>&1 &
socat -u TCP-LISTEN:143,reuseaddr,fork - >/dev/null 2>&1 &

exec charon
