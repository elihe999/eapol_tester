## Base image
FROM alpine

## Dockerfile author
MAINTAINER Johannes Luther <joe@netgab.net>

## Install packages
RUN apk update && apk upgrade && \
  apk add --update --no-cache \
  gcc make openssl-dev libnl-dev musl-dev linux-headers

## Create files and directories
RUN wget https://w1.fi/releases/wpa_supplicant-2.6.tar.gz -P /tmp/ && \
  cd /tmp && \
  tar xzf /tmp/wpa_supplicant-2.6.tar.gz

## Change building config that the eapol_test binary is created
RUN cp /tmp/wpa_supplicant-2.6/wpa_supplicant/defconfig /tmp/wpa_supplicant-2.6/wpa_supplicant/.config && \
  sed s/#CONFIG_EAPOL_TEST=y/CONFIG_EAPOL_TEST=y/g /tmp/wpa_supplicant-2.6/wpa_supplicant/.config

## Compile
RUN cd /tmp/wpa_supplicant-2.6/wpa_supplicant/ && \
  make eapol_test 

## Copy and clean up
RUN cp /tmp/wpa_supplicant-2.6/wpa_supplicant/eapol_test /usr/local/bin && \
  rm -r /tmp/wpa_supplicant*

#COPY *.sh /etc/rad1x/scripts/
#COPY config /etc/rad1x/config/

ENTRYPOINT ["/bin/sh"]

#CMD ["radiusd","-Xx","-f"]
