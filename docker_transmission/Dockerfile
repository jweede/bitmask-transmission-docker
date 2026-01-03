FROM lscr.io/linuxserver/transmission:4.0.5
COPY custom-cont-init.d/* /custom-cont-init.d/
COPY crontabs/* /etc/crontabs/
COPY transmission_settings.py /
RUN chmod +x /transmission_settings.py
