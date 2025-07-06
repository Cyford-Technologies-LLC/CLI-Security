# Cyford Security Mail Stack
FROM ubuntu:22.04

# Prevent interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Add fail2ban and iptables for testing
RUN apt-get update && apt-get install -y fail2ban iptables && \
    echo '[postfix]' > /etc/fail2ban/jail.local && \
    echo 'enabled = true' >> /etc/fail2ban/jail.local && \
    echo '[dovecot]' >> /etc/fail2ban/jail.local && \
    echo 'enabled = true' >> /etc/fail2ban/jail.local

# Install packages (without squirrelmail)
RUN apt-get update && apt-get install -y \
    postfix \
    dovecot-core \
    dovecot-imapd \
    dovecot-pop3d \
    php8.1 \
    php8.1-cli \
    php8.1-sqlite3 \
    php8.1-curl \
    php8.1-imap \
    apache2 \
    fail2ban \
    iptables \
    git \
    curl \
    wget \
    nano \
    supervisor \
    sudo \
    && rm -rf /var/lib/apt/lists/*

# Create required users
RUN useradd -r -s /bin/false report-ip

# Create directory structure
RUN mkdir -p /usr/local/share/cyford/security \
    && mkdir -p /var/log/cyford-security \
    && mkdir -p /var/spool/cyford-security

# Copy CLI Security files
COPY . /usr/local/share/cyford/security/

# Set permissions
RUN chown -R report-ip:report-ip /usr/local/share/cyford/security \
    && chown -R report-ip:report-ip /var/log/cyford-security \
    && chmod -R 755 /usr/local/share/cyford/security

# Create simple webmail interface
RUN echo '<?php phpinfo(); ?>' > /var/www/html/index.php \
    && chown -R www-data:www-data /var/www/html

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