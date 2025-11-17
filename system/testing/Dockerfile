# Cyford Security Testing Mail Stack
FROM ubuntu:22.04

# Prevent interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Install all required packages
RUN apt-get update && apt-get install -y \
    postfix \
    dovecot-core \
    dovecot-imapd \
    dovecot-pop3d \
    php8.1 \
    php8.1-cli \
    php8.1-sqlite3 \
    php8.1-curl \
    apache2 \
    squirrelmail \
    fail2ban \
    iptables \
    git \
    curl \
    wget \
    nano \
    supervisor \
    && rm -rf /var/lib/apt/lists/*

# Create required users
RUN useradd -r -s /bin/false report-ip

# Create directory structure
RUN mkdir -p /opt/cyford/security \
    && mkdir -p /var/log/cyford-security \
    && mkdir -p /var/spool/cyford-security

# Set permissions
RUN chown -R report-ip:report-ip /var/log/cyford-security \
    && chown -R report-ip:report-ip /var/spool/cyford-security

# Configure SquirrelMail
RUN ln -s /usr/share/squirrelmail /var/www/html/webmail \
    && chown -R www-data:www-data /var/lib/squirrelmail

# Create supervisor config
RUN echo '[supervisord]' > /etc/supervisor/conf.d/mailstack.conf \
    && echo 'nodaemon=true' >> /etc/supervisor/conf.d/mailstack.conf \
    && echo '' >> /etc/supervisor/conf.d/mailstack.conf \
    && echo '[program:postfix]' >> /etc/supervisor/conf.d/mailstack.conf \
    && echo 'command=/usr/sbin/postfix start-fg' >> /etc/supervisor/conf.d/mailstack.conf \
    && echo 'autorestart=true' >> /etc/supervisor/conf.d/mailstack.conf \
    && echo '' >> /etc/supervisor/conf.d/mailstack.conf \
    && echo '[program:dovecot]' >> /etc/supervisor/conf.d/mailstack.conf \
    && echo 'command=/usr/sbin/dovecot -F' >> /etc/supervisor/conf.d/mailstack.conf \
    && echo 'autorestart=true' >> /etc/supervisor/conf.d/mailstack.conf \
    && echo '' >> /etc/supervisor/conf.d/mailstack.conf \
    && echo '[program:apache2]' >> /etc/supervisor/conf.d/mailstack.conf \
    && echo 'command=/usr/sbin/apache2ctl -DFOREGROUND' >> /etc/supervisor/conf.d/mailstack.conf \
    && echo 'autorestart=true' >> /etc/supervisor/conf.d/mailstack.conf

# Expose ports
EXPOSE 25 110 143 993 995 80

# Start supervisor
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/mailstack.conf"]