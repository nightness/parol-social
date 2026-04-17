#!/bin/sh
# Write build-info.js at startup so DEV_MODE env var takes effect without a rebuild.
# DEV_MODE env var wins over the baked-in PAROLNET_DEV_MODE build arg.
_dev="${DEV_MODE:-${PAROLNET_DEV_MODE:-false}}"
echo "window.BUILD_INFO={date:'v${PAROLNET_BUILD_VERSION} ${PAROLNET_BUILD_COMMIT} ${PAROLNET_BUILD_DATE}',dev:${_dev}};" \
    > /usr/share/nginx/html/pwa/build-info.js
echo "Build: v${PAROLNET_BUILD_VERSION} ${PAROLNET_BUILD_COMMIT} | dev=${_dev}"

# Start TURN/STUN server if configured
if [ -n "$TURN_SECRET" ] && [ -n "$TURN_EXTERNAL_IP" ]; then
    envsubst '${TURN_SECRET} ${TURN_EXTERNAL_IP} ${TURN_REALM}' \
        < /etc/turnserver.conf.template > /etc/turnserver.conf
    turnserver -c /etc/turnserver.conf &
    echo "TURN/STUN server started on :3478 (external: $TURN_EXTERNAL_IP)"
else
    echo "TURN/STUN server not configured (set TURN_SECRET + TURN_EXTERNAL_IP to enable)"
fi

# Start relay server in background
echo "Starting ParolNet relay on port 9000..."
/usr/local/bin/parolnet-relay &

# Start nginx in foreground
echo "Starting nginx..."
exec nginx -g 'daemon off;'
