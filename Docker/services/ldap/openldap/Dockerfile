FROM protocol-base-ubuntu:latest
RUN apt-get update && apt-get install -y --no-install-recommends \
    slapd ldap-utils && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /var/lib/ldap /etc/ldap/slapd.d && \
    chown openldap:openldap /var/lib/ldap /etc/ldap/slapd.d
EXPOSE 389
CMD ["/usr/sbin/slapd", "-d", "0", "-h", "ldap:/// ldaps:///"]
