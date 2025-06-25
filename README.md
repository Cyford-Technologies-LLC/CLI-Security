# CLI-Security
API Security  for CLI functions and applications

#  Instructions  are for debian based..   But redhat  shouldn't be  to different
#  Script is tested under php 8+  not sure lowest requirement yet


sudo apt update && sudo apt install php-cli unzip curl  git -y
curl -sS https://getcomposer.org/installer | php
sudo php composer-setup.php --install-dir=/usr/local/bin --filename=composer

sudo mkdir -p /usr/local/share/cyford/security

Git clone https://github.com/Cyford-Technologies-LLC/CLI-Security.git /usr/local/share/cyford/security

cd /usr/local/share/cyford/security

#  Install composer
# For Debian/Ubuntu

sudo apt install php-cli unzip curl -y


     sudo ln -s /usr/local/share/cyford/report-ip/index.php /usr/local/bin/cyford-report

     sudo chmod +x /usr/local/share/cyford/report-ip/index.php





composer install











#  ##### Postfix
1. Add a Postfix content filter in `main.cf`:
   2.    content_filter = security-filter:dummy
1. Define your filter in `master.cf`:
   3.    security-filter unix - n n - - pipe
         flags=Rq user=report-ip argv=/usr/local/bin/report-ip --ips=${client_address} --categories=3


sudo systemctl restart postfix


