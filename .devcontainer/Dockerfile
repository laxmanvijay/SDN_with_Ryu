FROM ubuntu:focal

USER root
WORKDIR /root

COPY Entrypoint.sh /

RUN apt-get -y update
RUN apt-get -y upgrade

RUN apt-get install -y \
    curl \
    sudo \
    git \
    iproute2 \
    iputils-ping \
    net-tools \
    openvswitch-switch \
    openvswitch-testcontroller \
    tcpdump \
    vim \
    x11-xserver-utils \
    xterm \
    python3 \
    python3-pip

RUN pip install mininet \
    pip install ryu

RUN chmod +x /Entrypoint.sh

EXPOSE 6633 6653 6640