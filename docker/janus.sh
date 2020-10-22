cd /root/mcu-janus-proxy
#git clone https://github.com/meetecho/janus-gateway.git

sh autogen.sh
./configure --prefix=/opt/janus \
            --disable-all-plugins \
            --disable-all-transports \
            --disable-all-handlers \
            --disable-all-loggers \
            --disable-rest \
            --disable-rabbitmq \
            --disable-mqtt \
            --disable-unix-sockets \
            --disable-nanomsg \
            --enable-plugin-nosip \
            --enable-websockets
make
make install
make configs
