# DEBIAN KVM & LXC (LAMP) 🐱‍👤

❗ **TO DO** :   
* ✔ Remplacer Debian par Alpine  (l'image fait 3 Mo au lieu de 200 pour Debian, lol) 
* ✔ Séparer les partitions /home, /tmp etc lors de l'installation   
* Créer un user normal sur Alpine (mb) (osef en fait)
* redirect sur le site wordpress au endpoint /
* ✔ rendre iptable persistant
* changer les ports
* 2FA debian ssh & admin wordpress (DUO)
* Firewall sur la lxc ?
* Refaire une installe propre quand tout sera vu   
* ✔ Conteneur : Allow INPUT 80, OUTPUT ESTABLISHED
* SNMPv2 to v3 (Cacti)
* Virer sudo 
* Voir pour mettre DNS/DHCP dans iptavles pour que la debian puisse attribuer l'ip (si jamais ça bug)

__________________________________________________________


## Installation debian chiffrée avec LVM 🔐
 * Au boot sélectionner partition chiffrée avec LVM.
 * Installer sudo

## Création d'un container LXC 📦
### Commandes de base
```bash
# Toutes les commandes commencent pas lxc-*
# Le -n n'est pas obligatoire
lxc-create -t alpine -n mon_conteneur # créer un conteneur nommé mon_conteneur avec une image debian
lxc-start -n mon_conteneur # start le conteneur
lxc-attach -n mon_conteneur # se connecter au conteneur
lxc-stop -n mon_conteneur # stop le conteneur
lxc-destroy -n mon_conteneur # détruit le conteneur
lxc-ls -f # liste les conteneurs
etc.
```

### Configuration de base 
```
apt install lxc
apt install dnsmasq-base
systemctl restart lxc-net
systemctl status lxc-net

# Si le service dnsmasq est sur la machine, le virer
systemctl stop dnsmasq
systemctl disable dnsmasq
```

#### Configuration de la conf par défaut (template)
_([faire gaffe depuis la v2.1 les configs ont changé](https://discuss.linuxcontainers.org/t/lxc-2-1-has-been-released/487), ici c'est pour la v3+)  _

Dans /etc/lxc/default.conf :

```bash
lxc.net.0.type = veth
lxc.net.0.link = lxcbr0 # Nom du bridge sur la machine hôte
lxc.net.0.flags = up
lxc.net.0.hwaddr = 00:16:3e:xx:xx:xx
lxc.apparmor.profile = generated
lxc.apparmor.allow_nesting = 1
```

Nous on veut une IP fixe pour que ce soit plus simple avec le webserver :)

Dans /etc/lxc/dhcp.conf :

```bash
dhcp-host=miniwiki,10.0.10.2 # nom_du_conteneur, ip
```

Puis  dans /etc/default/lxc-net :

```bash
USE_LXC_BRIDGE="true"
LXC_DHCP_CONFILE=/etc/lxc/dhcp.conf
LXC_ADDR="10.0.10.1" # Adresse de l'interface lxcbr0
LXC_NETWORK="10.0.10.0/24"
LXC_DHCP_RANGE="10.0.10.100,10.0.10.200"
LXC_DOMAIN="peterpan.io"
```

puis on restart le service lxd-net :   

```bash
systemctl restart lxc-net
```

Et hop une ip fixe sera attribuée sur le conteneur :)

### Création du conteneur & connexion

```bash
lxc-create -t alpine -n miniwiki
lxc-start -n miniwiki
lxc-ls -f # montre les conteneurs avec leurs ip
lxc-attach -n miniwiki# connexion au conteneur
lxc-attach -n miniwiki -- ls -lh /home # execute une commande sur le conteneur sans y entrer

```

### Set autostart du conteneur

```bash
 echo "lxc.start.auto = 1" >> /var/lib/lxc/miniwiki/config
```

On peut par la suite faire un `lxc-autostart --list` et un `lxc-autostart` pour lancer les conteneurs avec l'option à 1


## Installation Apache, MySQL, phpMyAdmin, Wordpress, VsFTPd 🌐

Ajouter les repos sur Alpine (pas obligatoire apparemment) :
```bash
cat > /etc/apk/repositories << EOF
http://dl-cdn.alpinelinux.org/alpine/v$(cat /etc/alpine-release | cut -d'.' -f1,2)/main
http://dl-cdn.alpinelinux.org/alpine/v$(cat /etc/alpine-release | cut -d'.' -f1,2)/community
EOF
```

On peut installer nano aussi si pas à laise avec vi : `apk add nano`

Commandes de base sur Alpine :

```bash
apk update
apk add nom_du_paquet # équivalent apt install
rc-status # liste les services
rc-update add nom_service # autostart au boot
rc-service nom_service start|stop|restart|status
```

### Apache & PHP

#### Installation de base

```bash
apk add apache2 php$phpverx-apache2
apk add php7-common php7-iconv php7-json php7-gd php7-curl php7-xml php7-mysqli php7-imap php7-cgi fcgi php7-pdo php7-pdo_mysql php7-soap php7-xmlrpc php7-posix php7-mcrypt php7-gettext php7-ldap php7-ctype php7-dom php7-session
apk add wget mysql mysql-client php-zlib
rc-update add apache2
rc-service apache2 start
```

#### Hardening

 * https://www.conftool.net/en/technical_documentation/security_hints.html
 * https://wiki.debian-fr.xyz/S%C3%A9curiser_Apache2

```bash
sed -i 's/ServerTokens OS/ServerTokens Prod/g' /etc/apache2/httpd.conf
sed -i 's/ServerSignature On/ServerSignature Off/g' /etc/apache2/httpd.conf
sed -i 's/disable_functions =/disable_functions = show_source, system, shell_exec, passthru, phpinfo, proc_open, proc_nice/g' /etc/php7/php.ini 
sed -i 's/display_errors = On/display_errors = Off/g' /etc/php7/php.ini 
sed -i "s|.*expose_php\s*=.*|expose_php = Off|g" /etc/php7/php.ini 

# sed -i 's/Options Indexes FollowSymLinks/Options Indexes FollowSymLinks/g' /etc/apache2/httpd.conf
```

```bash
# Remplacez le <Directory /> de base par celui-ci :
<Directory />
    AllowOverride none
    Require all denied
    Order Allow,Deny
    Allow from all
    Options -Indexes -ExecCGI -Includes
</Directory>

```

```bash
cat >> /etc/apache2/conf.d/anti-ddos.conf << EOF 
MaxClients 150
KeepAlive On
MaxKeepAliveRequests 100
KeepAliveTimeout 10
EOF
```


### MySQL

```bash
apk add mysql mysql-client
mysql_install_db --user=mysql --datadir=/var/lib/mysql
rc-service mariadb start

# secure install de base
mysql_secure_installation

# config écoute que sur le local
sed -i "s|.*bind-address\s*=.*|bind-address=127.0.0.1|g" /etc/my.cnf.d/mariadb-server.cnf

# run mariadb au boot
rc-update add mariadb default # default pas obligatoire, il est pas défaut
rc-service mariadb restart

# connexion
mysql -u root -p'password_defini'
```

### phpMyAdmin

```bash
apk add phpmyadmin
chown -R apache:apache /etc/phpmyadmin/
chown -R apache:apache /usr/share/webapps/
ln -s /usr/share/webapps/phpmyadmin/ /var/www/localhost/htdocs/phpmyadmin
rc-service apache2 restart
```

### VsFTPd

```bash
apk add vsftpd
sed -i "s|.*anonymous_enable\s*=.*|anonymous_enable=NO|g" /etc/vsftpd/vsftpd.conf
sed -i "s|.*local_enable\s*=.*|local_enable=YES|g" /etc/vsftpd/vsftpd.conf
sed -i "s|.*local_umask\s*=.*|local_umask=022|g" /etc/vsftpd/vsftpd.conf
sed -i "s|.*write_enable\s*=.*|write_enable=YES|g" /etc/vsftpd/vsftpd.conf
sed -i "s|.*ftpd_banner\s*=.*|ftpd_banner=Salut les petit potes|g" /etc/vsftpd/vsftpd.conf
sed -i "s|.*connect_from_port_20\s*=.*|connect_from_port_20=NO|g" /etc/vsftpd/vsftpd.conf
echo "seccomp_sandbox=NO" >> /etc/vsftpd/vsftpd.conf && "pasv_enable=NO" >> /etc/vsftpd/vsftpd.conf
rc-service vsftpd start
rc-update add vsftpd
```

### Wordpress

 * https://www.hostinger.fr/tutoriels/wp-cli/

```bash
mkdir -p /usr/share/webapps/
cd /usr/share/webapps/
wget http://wordpress.org/latest.tar.gz
tar -xzvf latest.tar.gz
rm latest.tar.gz
chown -R apache:apache /usr/share/webapps/
ln -s /usr/share/webapps/wordpress/ /var/www/localhost/htdocs/wordpress

# Création de la BDD pour Wordpress
mysql -u root -p
CREATE DATABASE secret_db_wordpress;
GRANT ALL PRIVILEGES ON secret_db_wordpress.* TO 'secret_usr_wordpress'@'localhost' IDENTIFIED BY 'wordpress password';
FLUSH PRIVILEGES;
EXIT
```

http://192.168.1.62/wordpress/

## Monitoring via Cacti & Munin
### Munin

port = 4949
munin-master = serveur qui monitorer
munin-node = serveurs à monitorer

#### Conteneur
```bash
apk add munin-node

echo "allow ^10\.0\.10\.1$">>/etc/munin/munin-node.conf

ln -sf /usr/lib/munin/plugins/cpu /etc/munin/plugins/cpu
ln -sf /usr/lib/munin/plugins/diskstats /etc/munin/plugins/diskstats
ln -sf /usr/lib/munin/plugins/fw_packets /etc/munin/plugins/fw_packets
ln -sf /usr/lib/munin/plugins/if_err_ /etc/munin/plugins/if_err_eth0
ln -sf /usr/lib/munin/plugins/if_ /etc/munin/plugins/if_eth0
ln -sf /usr/lib/munin/plugins/load /etc/munin/plugins/load
ln -sf /usr/lib/munin/plugins/memory /etc/munin/plugins/memory
ln -sf /usr/lib/munin/plugins/munin_stats /etc/munin/plugins/munin_stats
ln -sf /usr/lib/munin/plugins/processes /etc/munin/plugins/processes
ln -sf /usr/lib/munin/plugins/uptime /etc/munin/plugins/uptime
ln -sf /usr/lib/munin/plugins/users /etc/munin/plugins/users
ln -sf /usr/lib/munin/plugins/threads /etc/munin/plugins/threads
ln -sf /usr/lib/munin/plugins/swap /etc/munin/plugins/swap


rc-update add munin-node
rc-service munin start
```

#### Machine hôte
```bash
apt install munin
ln -s /var/cache/munin/www/ /var/www/html/munin-interface

echo "[wordpress.localdomain]" >> /etc/munin/munin.conf
echo "    address 10.0.10.2" >> /etc/munin/munin.conf
echo "    use_node_name yes" >> /etc/munin/munin.conf

systemctl restart munin

# thème boostrap
cd /etc/munin
git clone https://github.com/munin-monitoring/contrib.git
mv /etc/munin/static /etc/munin/static.orig
mv /etc/munin/templates /etc/munin/templates.orig

cp -pr contrib/templates/munstrap/static /etc/munin/
cp -pr contrib/templates/munstrap/templates /etc/munin/
```

Accès : http://192.168.1.62:8080/munin-interface/

### Cacti
#### Machine hôte
```bash
# Conf base
sudo apt install -y apache2 mariadb-server mariadb-client libapache2-mod-php php-xml php-ldap php-mbstring php-gd php-gmp php-mysql
mysql_secure_installation

```

```bash
apt install cacti

# Suivre l'installation (apache2, création du daemon mysql etc puis se co http://192.168.1.62:8080/cacti avec admin:admin ou admin:mdp défini pour le user cacti

chmod -R 777 /usr/share/cacti/

# Puis créer un device à monitorer (127.0.0.1)

php -q poller.php --force
```

#### Conteneur

```bash
apk add snmp

~jsp le reste
```

## Règles iptables

#### /sbin/iptables-fw.sh
```bash

#!/bin/bash
# iptables firewall

# iptables configuration
fw_start() {
  iptables -P INPUT DROP
  iptables -P FORWARD DROP
  iptables -P OUTPUT DROP

  # Accept traffic on localhost
  iptables -A INPUT -i lo -j ACCEPT
  iptables -A OUTPUT -o lo -j ACCEPT

  # Add SSH
  iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT

  # Add FTP
  iptables -A INPUT -p tcp --dport 21 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT

  # Add Munin & Cacti
  iptables -A INPUT -p tcp --dport 8000 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT


  # Add Forwarding to Web Server
  iptables -A INPUT -i lxcbr0 -j ACCEPT # curl 10.0.10.2
  iptables -A FORWARD -i lxcbr0 -o ens33 -j ACCEPT
  iptables -A FORWARD -i ens33 -o lxcbr0 -j ACCEPT
  iptables -A INPUT -p tcp --dport 80 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT

  # Toutes les connexions déjà établies ont l'autorisation de sortir
  iptables -I OUTPUT 1 -m state --state RELATED,ESTABLISHED -j ACCEPT
}

# clear iptables configuration
fw_stop() {
  iptables -F
  iptables -X
  iptables -P INPUT   ACCEPT
  iptables -P FORWARD ACCEPT
  iptables -P OUTPUT  ACCEPT
}

# execute action
case "$1" in
  start|restart)
    echo "Starting firewall"
    fw_stop
    fw_start
    ;;
  stop)
    echo "Stopping firewall"
    fw_stop
    ;;
esac

# 192.168.1.63 = ip de la machine virtuelle (hôte)
# 10.0.10.2 = ip conteneur
```

#### /etc/systemd/system/iptables-fw.service
```bash
[Unit]
Description=iptables firewall service
After=network.target

[Service]
Type=oneshot
ExecStart=/sbin/iptables-fw.sh start
RemainAfterExit=true
ExecStop=/sbin/iptables-fw.sh stop
StandardOutput=journal

[Install]
WantedBy=multi-user.target

```

```bash
systemctl enable iptables-fw
systemctl start iptables-fw
```

## Hardening

* https://www.cyberciti.biz/tips/linux-security.html
* Isoler processus
* [Optimiser apache](http://rousseau-alexandre.fr/tutorial/2018/04/03/optimiser-apache.html) (virer version etc)
* Virer sudo etc 
* 2FA wordpress
* MySQL localhost
* User Mysql avec les bon droits + bon bind (pas de %)
* Virer connexion root en ssh etc
* Désactiver les API XMLRPC et JSON du wordpress




________________________
## Sources

https://angristan.xyz/2018/02/setup-network-bridge-lxc-net/
https://wiki.alpinelinux.org/wiki/Install_Alpine_on_LXC
http://rousseau-alexandre.fr/tutorial/2017/11/16/installer-apache.html
https://www.cyberciti.biz/faq/how-to-auto-start-lxd-containers-at-boot-time-in-linux/ (LXD)  
https://www.linuxembedded.fr/2013/07/configuration-reseau-de-lxc/
https://subscription.packtpub.com/book/virtualization_and_cloud/9781785888946/3/ch03lvl1sec17/autostarting-lxc-containers
https://wiki.alpinelinux.org/wiki/Setting_Up_Apache_with_PHP
https://wiki.alpinelinux.org/wiki/Nginx_with_PHP
https://www.cyberciti.biz/faq/how-to-enable-and-start-services-on-alpine-linux/
https://wiki.alpinelinux.org/wiki/MariaDB
https://wiki.alpinelinux.org/wiki/Production_LAMP_system:_Lighttpd_%2B_PHP_%2B_MySQL
https://wiki.alpinelinux.org/wiki/PhpMyAdmin
https://devdocs.prestashop.com/1.7/basics/installation/
https://www.alibabacloud.com/blog/how-to-install-and-configure-lxc-container-on-ubuntu-16-04_594090

https://munin.readthedocs.io/en/latest/index.html

https://www.itzgeek.com/how-tos/linux/debian/how-to-install-cacti-on-debian-9-stretch.html
https://www.itzgeek.com/how-tos/linux/how-to-monitor-remote-linux-servers-with-cacti.html
https://www.digitalocean.com/community/tutorials/how-to-forward-ports-through-a-linux-gateway-with-iptables#configuring-the-firewall-to-forward-port-80#