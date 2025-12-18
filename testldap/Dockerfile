FROM glauth/glauth
COPY default-config.cfg /app/config/config.cfg
COPY key.pem /key.pem
COPY cert.pem /cert.pem
# Expose web and LDAP ports
EXPOSE 389 636 5555

#ENTRYPOINT ["/usr/bin/dumb-init", "--"]
#CMD ["/bin/sh", "/app/docker/start.sh"]

