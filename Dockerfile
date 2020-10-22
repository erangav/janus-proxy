FROM  10.106.146.20:5001/janus-base-image:latest

# Clone, build and install the gateway
COPY . /root/mcu-janus-proxy/
RUN bash /root/mcu-janus-proxy/docker/janus.sh

ARG env

# Define the default start-up command
CMD ["bash", "/root/mcu-janus-proxy/docker/startup.sh"]


