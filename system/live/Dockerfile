# Cyford Security Live Production
FROM ubuntu:22.04

# Prevent interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Install required packages for system integration
RUN apt-get update && apt-get install -y \
    php8.1 \
    php8.1-cli \
    php8.1-sqlite3 \
    php8.1-curl \
    curl \
    wget \
    nano \
    git \
    openssh-client \
    systemd \
    dbus \
    ca-certificates \
    gnupg \
    lsb-release \
    && rm -rf /var/lib/apt/lists/*

# Add Docker group (GID 999 is common for Docker)
RUN groupadd -g 999 docker || true

# Create required users and groups
RUN useradd -r -s /bin/false report-ip \
    && groupadd -r postfix || true \
    && usermod -a -G postfix,docker report-ip

# Create directory structure
RUN mkdir -p /opt/cyford/security \
    && mkdir -p /var/log/cyford-security \
    && mkdir -p /var/spool/cyford-security \
    && mkdir -p /var/spool/postfix

# Set permissions
RUN chown -R report-ip:report-ip /var/log/cyford-security \
    && chown -R report-ip:postfix /var/spool/cyford-security \
    && chmod -R 775 /var/spool/cyford-security

# Copy initialization script
COPY live-setup.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/live-setup.sh

# Set working directory
WORKDIR /opt/cyford/security

# Start with initialization
CMD ["/usr/local/bin/live-setup.sh"]