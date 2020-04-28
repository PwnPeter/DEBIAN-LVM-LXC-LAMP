# DEBIAN KVM & LXC (LAMP) 🐱‍👤

❗ **TO DO** :   
 * https://blog.marcfredericgomez.fr/guide-de-durcissement-dun-serveur-linux-pour-pci-dss/
 * https://www.noobunbox.net/serveur/monitoring/configurer-snmp-v3-sous-debian

Installation automatique via ansible disponible ici : https://github.com/pierreployet/playbooks
__________________________________________________________

## Prérequis
 * Toutes les commandes suivantes seront exécutées en tant que root.
 * Ajouter dans votre fichier host `ip_du_serveur miniwiki.io`
(ici l'ip publique est 192.168.1.72) donc :
echo "192.168.1.72 miniwiki.io >> /etc/hosts
(Veuillez à bien modifier l'ip et nom d'hôte en fonction de vos besoins)


## Installation debian chiffrée avec LVM 🔐
 * Au boot sélectionner partition chiffrée avec LVM.
 * Installer sudo

```bash
apt install sudo
usermod -aG sudo peterpan # on donne les droits sudo à l'user créé à l'installation du serveur
```


Sur la machine cliente :
```bash
# Générer une paire de clé RSA sur la machine cliente
ssh-keygen

# Copie de la public key sur le serveur debian
ssh-copy-id peterpan@miniwiki.io

ssh peterpan@miniwiki.io

cat >> /etc/ssh/sshd_config << EOF
PasswordAuthentication no
RSAAuthentication yes
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
PermitRootLogin no
Port 2202
Banner /etc/issue.net
EOF

cat > /etc/issue.net << EOF
Projet Linux Avancé #1

Authors : X

Tout accès non autorisé au serveur peut entrainer des poursuites judiciaires.
EOF

systemctl restart sshd
```

Une fois le service sshd redémarré l'authentification se fera désormais par publickey sur le port 2202 :)

`ssh peterpan@miniwiki.io -p 2202`


## Création d'un container LXC 📦
### Commandes de base ℹ
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
apt install lxc dnsmasq-base -y
systemctl restart lxc-net
systemctl status lxc-net

# Si le service dnsmasq est sur la machine, le virer
systemctl stop dnsmasq
systemctl disable dnsmasq
```

#### Configuration de la conf par défaut (template)
__ ([Depuis la v2.1 les configs ont changé](https://discuss.linuxcontainers.org/t/lxc-2-1-has-been-released/487), ici c'est pour la v3+) __


```bash
cat > /etc/lxc/default.conf << EOF
lxc.net.0.type = veth
lxc.net.0.link = lxcbr0
lxc.net.0.flags = up
lxc.net.0.hwaddr = 00:16:3e:xx:xx:xx
lxc.apparmor.profile = generated
lxc.apparmor.allow_nesting = 1
EOF


# Nous on veut une IP fixe pour que ce soit plus simple avec le webserver :)


echo "dhcp-host=miniwiki,10.0.10.2" >  /etc/lxc/dhcp.conf # nom_du_conteneur, ip

# Conf de base du DHCP

cat > /etc/default/lxc-net << EOF
USE_LXC_BRIDGE="true"
LXC_DHCP_CONFILE=/etc/lxc/dhcp.conf
LXC_ADDR="10.0.10.1"
LXC_NETWORK="10.0.10.0/24"
LXC_DHCP_RANGE="10.0.10.100,10.0.10.200"
LXC_DOMAIN="peterpan.io"
EOF

systemctl restart lxc-net
```

Et hop une ip fixe sera attribuée sur le conteneur :)

### Création du conteneur

```bash
# Ici on fait le choix de créer un conteneur alpine pour sa taille réduite (3 Mo) et sa surface d'attaque très réduite (peu de services installés)

lxc-create -t alpine -n miniwiki
lxc-start -n miniwiki
lxc-ls -f # montre les conteneurs avec leurs ip
#lxc-attach -n miniwiki # connexion au conteneur
#lxc-attach -n miniwiki -- ls -lh /home # execute une commande sur le conteneur sans y entrer

```

### Set autostart du conteneur

```bash
echo "lxc.start.auto = 1" >> /var/lib/lxc/miniwiki/config
```

On peut par la suite faire un `lxc-autostart --list` et un `lxc-autostart` pour lancer les conteneurs avec l'option à 1


## Installation Apache, MySQL, phpMyAdmin, Wordpress, VsFTPd 🌐

Ajouter les repos sur Alpine (si les commandes ci-dessous ne fonctionnent pas) :
```bash
lxc-attach miniwiki

cat > /etc/apk/repositories << EOF
http://dl-cdn.alpinelinux.org/alpine/v$(cat /etc/alpine-release | cut -d'.' -f1,2)/main
http://dl-cdn.alpinelinux.org/alpine/v$(cat /etc/alpine-release | cut -d'.' -f1,2)/community
EOF
```

On peut également installer nano aussi si pas à laise avec vi : `apk add nano`

### Commandes de base sur Alpine :

```bash
apk update
apk upgrade
apk add nom_du_paquet # équivalent apt install
rc-status # liste les services
rc-update add nom_service # autostart au boot
rc-service nom_service start|stop|restart|status
```

### Apache & PHP

#### Installation

```bash
apk add apache2 php$phpverx-apache2 apache2-ssl apache2-utils
apk add php7-common php7-iconv php7-json php7-gd php7-curl php7-xml php7-mysqli php7-imap php7-cgi fcgi php7-pdo php7-pdo_mysql php7-soap php7-xmlrpc php7-posix php7-mcrypt php7-gettext php7-ldap php7-ctype php7-dom php7-session php-phar
apk add wget mysql mysql-client php-zlib

rm /var/www/localhost/htdocs/index.html

rm -f /etc/ssl/apache2/*
openssl genrsa 2048 > /etc/ssl/apache2/server.key 

printf "FR\nGithub\nLXC\nAlpine\nPeterPan\nminiwiki.io\ncontact@miniwiki.io\n" | openssl req -new -key /etc/ssl/apache2/server.key -x509 -days 365 -set_serial $RANDOM -out /etc/ssl/apache2/server.pem

sed -i 's/ServerName www.example.com:443/ServerName miniwiki.io:443/g' /etc/apache2/conf.d/ssl.conf
sed -i 's/SSLProtocol all -SSLv3/SSLProtocol All -SSLv2 -SSLv3 -TLSv1 -TLSv1.1/g' /etc/apache2/conf.d/ssl.conf

cat >> /etc/apache2/conf.d/ssl.conf << EOF
<VirtualHost *:80>
        ServerName miniwiki.io:80
        DocumentRoot "/var/www/localhost/htdocs"
        Redirect permanent / https://miniwiki.io
</VirtualHost>
EOF



sed -i 's/ServerTokens OS/ServerTokens Prod/g' /etc/apache2/httpd.conf
sed -i 's/ServerSignature On/ServerSignature Off/g' /etc/apache2/httpd.conf
sed -i 's|#LoadModule rewrite_module modules/mod_rewrite.so|LoadModule rewrite_module modules/mod_rewrite.so|g' /etc/apache2/httpd.conf
sed -i 's|Listen 80|Listen 10.0.10.2:80|g' /etc/apache2/httpd.conf
sed -i 's|Listen 443|Listen 10.0.10.2:443|g' /etc/apache2/conf.d/ssl.conf




echo "TraceEnable Off" >> /etc/apache2/httpd.conf
echo "Options all -Indexes" >> /etc/apache2/httpd.conf
echo "Header always unset X-Powered-By" >> /etc/apache2/httpd.conf

sed -i 's/display_errors = On/display_errors = Off/g' /etc/php7/php.ini 
sed -i "s|.*expose_php\s*=.*|expose_php = Off|g" /etc/php7/php.ini 

# sed -i 's/Options Indexes FollowSymLinks/Options Indexes FollowSymLinks/g' /etc/apache2/httpd.conf

# Remplacez le <Directory /> de base par celui-ci :
<Directory />
    AllowOverride none
    Require all denied
    Order Allow,Deny
    Allow from all
    Options -Indexes -ExecCGI -Includes
</Directory>

cat >> /etc/apache2/conf.d/anti-ddos.conf << EOF 
MaxClients 150
KeepAlive On
MaxKeepAliveRequests 100
KeepAliveTimeout 10
EOF

cat > /etc/apache2/conf.d/rewrite-wordpress-url.conf << EOF
<Directory "/var/www/localhost/htdocs">
    RewriteEngine on
    RewriteCond %{HTTP_HOST} ^(www.)?miniwiki.io$
    RewriteCond %{REQUEST_URI} !^/wordpress/
    RewriteCond %{REQUEST_FILENAME} !-f
    RewriteCond %{REQUEST_FILENAME} !-d
    RewriteRule ^(.*)$ /wordpress/$1
    RewriteCond %{HTTP_HOST} ^(www.)?miniwiki.io$
    RewriteRule ^(/)?$ wordpress/index.php [L]
</Directory>

# On bloque l'API XMLRPC pour éviter les bruteforces/Ddos
<Files xmlrpc.php>
    order deny,allow
    deny from all
</Files>

EOF

rc-update add apache2
rc-service apache2 start
```


### MySQL

```bash
apk add mysql mysql-client
mysql_install_db --user=mysql --datadir=/var/lib/mysql
rc-update add mariadb default # default pas obligatoire, il est pas défaut
rc-service mariadb start


# secure install de base
printf "\nn\nn\ny\ny\ny\ny\n" | mysql_secure_installation
mysql -e "SET PASSWORD FOR root@localhost = PASSWORD('mdp_root');FLUSH PRIVILEGES;" 


# config écoute que sur le local
sed -i "s|.*bind-address\s*=.*|bind-address=127.0.0.1|g" /etc/my.cnf.d/mariadb-server.cnf

# run mariadb au boot
rc-service mariadb restart

# connexion
mysql -u root -p'mdp_root'
```

### phpMyAdmin

```bash
apk add phpmyadmin
chown -R apache:apache /etc/phpmyadmin/
chown -R apache:apache /usr/share/webapps/
# ln -s /usr/share/webapps/phpmyadmin/ /var/www/localhost/htdocs/phpmyadmin


htpasswd -c -b /etc/apache2/.htpasswd admin mdp_admin
chmod 600 /etc/apache2/.htpasswd
chown apache:apache /etc/apache2/.htpasswd

cat > /etc/apache2/conf.d/phpmyadmin.conf << EOF
Alias /adminmyphp "/usr/share/webapps/phpmyadmin"
<Directory "/usr/share/webapps/phpmyadmin">
        AuthType Basic
        AuthName "Password Required"
        AuthUserFile /etc/apache2/.htpasswd
        Require valid-user
        AddDefaultCharset UTF-8
        AllowOverride All
        Options FollowSymlinks
        <IfModule mod_authz_core.c>
        #       Require all granted
        </IfModule>
</Directory>
<Directory "/usr/share/webapps/phpmyadmin/libraries">
        <IfModule mod_authz_core.c>
                Require all denied
        </IfModule>
</Directory>
<Directory "/usr/share/webapps/phpmyadmin/templates">
        <IfModule mod_authz_core.c>
                Require all denied
        </IfModule>
</Directory>
EOF

echo "\$cfg['Servers'][\$i]['AllowRoot'] = false;" >> /etc/phpmyadmin/config.inc.php

sed -i "s|$cfg['blowfish_secret'] = ''; /* YOU MUST FILL IN THIS FOR COOKIE AUTH! */;|$cfg['blowfish_secret'] = '$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 32)';|g" /etc/phpmyadmin/config.inc.php


#phpmyadmin user
# mysql -e "CREATE USER 'pmauser'@'localhost' IDENTIFIED BY 'password_here';GRANT ALL PRIVILEGES ON *.* TO 'pmauser'@'localhost' WITH GRANT OPTION;"

rc-service apache2 restart

https://miniwiki.io/adminmyphp
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
sed -i "s|.*chroot_local_user\s*=.*|chroot_local_user=YES|g" /etc/vsftpd/vsftpd.conf
echo "seccomp_sandbox=NO" >> /etc/vsftpd/vsftpd.conf && echo "pasv_enable=YES" >> /etc/vsftpd/vsftpd.conf
echo "listen_port=2121" >> /etc/vsftpd/vsftpd.conf
echo "listen_address=10.0.10.2" >> /etc/vsftpd/vsftpd.conf
echo "allow_writeable_chroot=YES" >> /etc/vsftpd/vsftpd.conf
echo "passwd_chroot_enable=yes" >> /etc/vsftpd/vsftpd.conf
  

apk add openssl

printf "FR\nGithub\nLXC\nAlpine\nPeterPan\nminiwiki.io\ncontact@miniwiki.io\n" | openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/ssl/private/vsftpd.pem -out /etc/ssl/private/vsftpd.pem

echo "rsa_cert_file=/etc/ssl/private/vsftpd.pem" >> /etc/vsftpd/vsftpd.conf
echo "rsa_private_key_file=/etc/ssl/private/vsftpd.pem" >> /etc/vsftpd/vsftpd.conf
echo "ssl_enable=YES" >> /etc/vsftpd/vsftpd.conf
echo "allow_anon_ssl=NO" >> /etc/vsftpd/vsftpd.conf
echo "force_local_data_ssl=YES" >> /etc/vsftpd/vsftpd.conf
echo "force_local_logins_ssl=YES" >> /etc/vsftpd/vsftpd.conf

echo "ssl_tlsv1=YES" >> /etc/vsftpd/vsftpd.conf

echo "ssl_sslv2=NO" >> /etc/vsftpd/vsftpd.conf

echo "ssl_sslv3=NO" >> /etc/vsftpd/vsftpd.conf

echo "require_ssl_reuse=NO" >> /etc/vsftpd/vsftpd.conf
echo "ssl_ciphers=HIGH" >> /etc/vsftpd/vsftpd.conf

rc-service vsftpd start
rc-update add vsftpd
```

### Wordpress

#### Installation wp-cli

```bash
cd /tmp
wget https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar
chmod +x wp-cli.phar
php wp-cli.phar --info
mv wp-cli.phar /usr/local/bin/wp

# Création de la BDD pour Wordpress
mysql -u root -p'mdp_root' -e "CREATE DATABASE secret_db_wordpress;GRANT ALL PRIVILEGES ON secret_db_wordpress.* TO 'secret_user_wordpress'@'localhost' IDENTIFIED BY 'wordpress_password';
FLUSH PRIVILEGES;"


# Installation de Wordpress

mkdir /usr/share/webapps/wordpress && cd /usr/share/webapps/wordpress
wp core download --allow-root
wp core config --dbname="secret_db_wordpress" --dbuser="secret_user_wordpress" --dbpass="wordpress_password" --dbhost="localhost" --dbprefix="miniwiki_wp_" --allow-root
wp core install --url="miniwiki.io/wordpress/" --title="MiniWiki" --admin_user="peterpan" --admin_password="motdepasse_administrateur" --admin_email="votre@email.com" --allow-root


mysql -u root -p'mdp_root' -D "secret_db_wordpress"  -e 'UPDATE miniwiki_wp_options SET option_value = "http://miniwiki.io/" WHERE option_name = "home";'

chown -Rf apache:apache /usr/share/webapps/
ln -s /usr/share/webapps/wordpress/ /var/www/localhost/htdocs/wordpress

rm -f /usr/share/webapps/wordpress/license.txt
rm -f /usr/share/webapps/wordpress/readme.html


# Installation d'un plugin pour le 2FA Authentication
    # DUO https://duo.com/docs/wordpress
wp plugin --allow-root --activate install duo-wordpress
    # OU Wordfence-login-security (fonctionne avec google autheitcator et permet également d'intégrer une captcha en générant les clés ici : https://www.wordfence.com/help/?query=module-login-security-captcha )
wp plugin --allow-root --activate install wordfence-login-security

# Installation d'un plugin de securité (WAF & Bruteforce détection)

wp plugin --allow-root install wordfence
chown -Rf apache:apache /usr/share/webapps
wp plugin --allow-root activate wordfence

chown -Rf apache:apache /usr/share/webapps


# On désactive les fonctions sensibles, wp cli ayant besoin de proc_open on réalise cette commande après l'installation.
sed -i 's/disable_functions =/disable_functions = show_source, system, shell_exec, passthru, phpinfo, proc_open, proc_nice/g' /etc/php7/php.ini 

# On créer un user vsftpd qui n'a accès qu'au dossier wordpress
printf "mdp_not_weak\nmdp_not_weak\n" | adduser -h /usr/share/webapps/wordpress/ -s /bin/


```

http://miniwiki.io/wordpress/wp-admin

## Monitoring via Cacti & Munin

### Apache (machine hôte)
```bash
apt install apache2 openssl php -y
echo "Listen 8000" > /etc/apache2/ports.conf

a2enmod ssl
a2enmod headers

mkdir /etc/ssl/apache2

openssl genrsa 2048 > /etc/ssl/apache2/server.key && printf "FR\nGithub\nLXC\nAlpine\nPeterPan\nminiwiki.io\ncontact@miniwiki.io\n" | openssl req -new -key /etc/ssl/apache2/server.key -x509 -days 365 -set_serial $RANDOM -out /etc/ssl/apache2/server.pem

cat > /etc/apache2/sites-available/hote-ssl-8000.conf << EOF
<VirtualHost *:8000>

        # Activation du SSL
        SSLEngine On

        ServerName miniwiki.io:8000

        # Activation de tous les protocoles sécurisés (TLS v1.3 et TLS v1.2) tout en désactivant les protocoles obsolètes (TLS v1.0 et 1.1) et ceux non sécurisés (SSL v2, SSL v3)
        SSLProtocol All -SSLv2 -SSLv3 -TLSv1 -TLSv1.1

        # On active les méthodes de chiffrement, et on désactive les méthodes de chiffrement non sécurisés (par la présence d'un !)
        SSLCipherSuite HIGH:!aNULL:!MD5:!ADH:!RC4:!DH:!RSA

        # Le navigateur devra choisir une méthode de chiffrement en respectant l'ordre indiquée dans SSLCipherSuite
        SSLHonorCipherOrder on

        # Chemin vers le certificat SSL de votre nom de domaine
        SSLCertificateFile "/etc/ssl/apache2/server.pem"

        # Chemin vers la clée privée du certificat SSL de votre nom de domaine
        SSLCertificateKeyFile "/etc/ssl/apache2/server.key"

        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined

        ErrorDocument 403 https://miniwiki.io/

        ErrorDocument 400 https://miniwiki.io/

</VirtualHost>
EOF

a2ensite hote-ssl-8000.conf

rm /var/www/html/index.html


sed -i 's/Options Indexes FollowSymLinks/Options -Indexes +FollowSymLinks/g' /etc/apache2/apache2.conf

sed -i 's/ServerTokens OS/ServerTokens Prod/g' /etc/apache2/conf-available/security.conf
sed -i 's/ServerSignature On/ServerSignature Off/g' /etc/apache2/conf-available/security.conf

sed -i 's/disable_functions =/disable_functions = show_source, system, shell_exec, passthru, phpinfo, proc_open, proc_nicen, /g' /etc/php/7.3/apache2/php.ini
sed -i 's/display_errors = On/display_errors = Off/g' /etc/php/7.3/apache2/php.ini
sed -i "s|.*expose_php\s*=.*|expose_php = Off|g" /etc/php/7.3/apache2/php.ini 

echo "TraceEnable Off" >> /etc/apache2/conf-available/security.conf
echo "Options all -Indexes" >> /etc/apache2/conf-available/security.conf
echo "Header always unset X-Powered-By" >> /etc/apache2/conf-available/security.conf

systemctl restart apache2
```

### Munin

#### Machine hôte
```bash
apt install munin munin-node munin-plugins-extra  git -y

mkdir -p /var/cache/munin/www

apt install apache2 libcgi-fast-perl libapache2-mod-fcgid -y

a2enmod fcgid

apt install munin munin-node munin-plugins-extra -y

sed -i "s|#dbdir  /var/lib/munin|dbdir  /var/lib/munin|g" /etc/munin/munin.conf

sed -i "s|#htmldir /var/cache/munin/www|htmldir /var/cache/munin/www|g" /etc/munin/munin.conf

sed -i "s|#logdir /var/log/munin|logdir /var/log/munin|g" /etc/munin/munin.conf

sed -i "s|#rundir  /var/run/munin|rundir  /var/run/munin|g" /etc/munin/munin.conf

sed -i "s|#tmpldir        /etc/munin/templates|tmpldir        /etc/munin/templates|g" /etc/munin/munin.conf

sed -i "s|localhost.localdomain|debian.io|g" /etc/munin/munin.conf

sed -i "s|    address 127.0.0.1|    address localhost|g" /etc/munin/munin.conf

ln -fs /etc/munin/apache24.conf /etc/apache2/conf-enabled/munin.conf

echo "[miniwiki.io]" >> /etc/munin/munin.conf
echo "    address 10.0.10.2" >> /etc/munin/munin.conf
echo "    use_node_name yes" >> /etc/munin/munin.conf

cat > /etc/munin/apache24.conf << EOF
# Munin configuration for apache2
# ***** COMMON SETTINGS FOR ALL STRATEGIES *****

ScriptAlias /munin-cgi/munin-cgi-graph /usr/lib/munin/cgi/munin-cgi-graph
Alias /munin/static/ /var/cache/munin/www/static/

<Directory /var/cache/munin/www>
#    Require local
     AuthType Basic
     AuthName "Password Required"
     AuthUserFile /etc/apache2/.htpasswd
     Require valid-user
     Order allow,deny
     Allow from all
#    Options FollowSymLinks SymLinksIfOwnerMatch
    Options None
</Directory>

<Directory /usr/lib/munin/cgi>
    Require local
    <IfModule mod_fcgid.c>
        SetHandler fcgid-script
    </IfModule>
    <IfModule !mod_fcgid.c>
        SetHandler cgi-script
    </IfModule>
</Directory>


# ***** SETTINGS FOR CGI/CRON STRATEGIES *****
Alias /munin /var/cache/munin/www
EOF

htpasswd -c -b /etc/apache2/.htpasswd admin mdp_admin

chmod 600 /etc/apache2/.htpasswd
chown www-data:www-data /etc/apache2/.htpasswd

munin-node-configure --shell | sh -x

dans /etc/munin/munin-node.conf mettre le host à 127.0.0.1

# thème bootstrap
cd /etc/munin
git clone https://github.com/munin-monitoring/contrib.git
mv /etc/munin/static /etc/munin/static.orig
mv /etc/munin/templates /etc/munin/templates.orig

cp -pr contrib/templates/munstrap/static /etc/munin/
cp -pr contrib/templates/munstrap/templates /etc/munin/

service apache2 restart
service munin-node start
service munin start

```

Accès : https://miniwiki.io:8000/munin/ (graphiques générés toutes les 5 mins)

#### Conteneur
```bash
apk add munin-node

echo "allow ^10\.0\.10\.1$">>/etc/munin/munin-node.conf

# ln -sf /usr/lib/munin/plugins/cpu /etc/munin/plugins/cpu
# ln -sf /usr/lib/munin/plugins/diskstats /etc/munin/plugins/diskstats
# ln -sf /usr/lib/munin/plugins/fw_packets /etc/munin/plugins/fw_packets
# ln -sf /usr/lib/munin/plugins/if_err_ /etc/munin/plugins/if_err_eth0
# ln -sf /usr/lib/munin/plugins/if_ /etc/munin/plugins/if_eth0
# ln -sf /usr/lib/munin/plugins/load /etc/munin/plugins/load
# ln -sf /usr/lib/munin/plugins/memory /etc/munin/plugins/memory
# ln -sf /usr/lib/munin/plugins/munin_stats /etc/munin/plugins/munin_stats
# ln -sf /usr/lib/munin/plugins/processes /etc/munin/plugins/processes
# ln -sf /usr/lib/munin/plugins/uptime /etc/munin/plugins/uptime
# ln -sf /usr/lib/munin/plugins/users /etc/munin/plugins/users
# ln -sf /usr/lib/munin/plugins/threads /etc/munin/plugins/threads
# ln -sf /usr/lib/munin/plugins/swap /etc/munin/plugins/swap
# ln -sf /usr/lib/munin/plugins/apache_accesses /etc/munin/plugins/apache_accesses
# ln -sf /usr/lib/munin/plugins/apache_processes /etc/munin/plugins/apache_processes
# ln -sf /usr/lib/munin/plugins/apache_volume /etc/munin/plugins/apache_volume
# ln -sf /usr/lib/munin/plugins/mysql_bytes /etc/munin/plugins/mysql_bytes
# ln -sf /usr/lib/munin/plugins/mysql_innodb /etc/munin/plugins/mysql_innodb
# ln -sf /usr/lib/munin/plugins/mysql_bytes /etc/munin/plugins/mysql_bytes
# ln -sf /usr/lib/munin/plugins/mysql_slowqueries /etc/munin/plugins/mysql_slowqueries
# ln -sf /usr/lib/munin/plugins/mysql_threads /etc/munin/plugins/mysql_threads

munin-node-configure --shell | sh -x

dans /etc/munin/munin-node.conf mettre le host à 10.0.10.2

rc-update add munin-node
rc-service munin-node start
```

### Cacti
#### Machine hôte
```bash
# Conf base
sudo apt install -y mariadb-server mariadb-client libapache2-mod-php php-xml php-ldap php-mbstring php-gd php-gmp php-mysql snmp php-snmp rrdtool librrds-perl cacti snmpd libsnmp-dev

systemctl stop snmpd

net-snmp-create-v3-user -ro -A mdp_auth -a SHA -X mdp_chiffrement -x AES user # Créer un user type Authpriv pour utliser snmpv3

systemctl start snmpd

snmpwalk -v3 -a SHA -A mdp_auth -x AES -X mdp_chiffrement -l authPriv -u user localhost | head -10


systemctl enable snmpd

# par défaut le user est admin et le mot de passe celui défini pendant l'installation de cacti, si ça ne fonctionne pas vous pouvez le changer avec la commande ci-dessous :
mysql -e "update cacti.user_auth set password=md5('admin') where username='admin';"

printf "\nn\nn\ny\ny\ny\ny\n" | mysql_secure_installation

# set mdp root pour la connexion locale
mysql -e "SET PASSWORD FOR root@localhost = PASSWORD('mdp_root');FLUSH PRIVILEGES;" 

sed -i "s|.*bind-address\s*=.*|bind-address=127.0.0.1|g" /etc/mysql/mariadb.conf.d/50-server.cnf

cat > /etc/apache2/conf-available/cacti.conf << EOF
Alias /cacti /usr/share/cacti/site

<Directory /usr/share/cacti/site>
        AuthType Basic
        AuthName "Password Required"
        AuthUserFile /etc/apache2/.htpasswd
        Require valid-user
        Options +FollowSymLinks
        AllowOverride None
        <IfVersion >= 2.3>
#               Require all granted
        </IfVersion>
        <IfVersion < 2.3>
                Order Allow,Deny
                Allow from all
        </IfVersion>

        AddType application/x-httpd-php .php

        <IfModule mod_php.c>
                php_flag magic_quotes_gpc Off
                php_flag short_open_tag On
                php_flag register_globals Off
                php_flag register_argc_argv On
                php_flag track_vars On
                # this setting is necessary for some locales
                php_value mbstring.func_overload 0
                php_value include_path .
        </IfModule>

        DirectoryIndex index.php
</Directory>

EOF

systemctl restart mariadb


# Suivre l'installation (apache2, création du daemon mysql etc puis se co https://miniwiki.io:8000/cacti avec admin:admin ou admin:mdp défini pour le user cacti

nano /etc/cacti/debian.php #Vérifier que c'est les bon credentials pour que cacti se co à la bdd

cat > /etc/cron.d/cacti << EOF
MAILTO=root
*/5 * * * * www-data php /usr/share/cacti/site/poller.php 2>&1 >/dev/null | if [ -f /usr/bin/ts ] ; then ts ; else tee ; fi >> /var/log/cacti/poller-error.log
EOF

chmod -R www-data:www-data /usr/share/cacti/

# Puis créer un device à monitorer (127.0.0.1)
```
https://miniwiki.io:8000/cacti


#### Conteneur

```bash
apk add net-snmp

sed -i 's/agentAddress  udp:127.0.0.1:161/agentAddress  udp:10.0.10.2:162/g' /etc/snmp/snmpd.conf # on met le port 152 car il y a un bug avec alpine, par défaut ik ouvrir également le port 161

echo 'createUser user2 SHA "mdp_auth2" AES mdp_chiffrement2' >> /var/lib/net-snmp/snmpd.conf


rc-update add snmpd
rc-service snmpd start

# Dans l'interface cacti (http://miniwiki.io:8000/cacti) créer un nouvelle équipement :
# nom de la machine : 10.0.10.2
# Device-Template : Net-SNMP-Device
# port SNMP 162
# Downed Device Detection : Ping or SNMP Uptime
# Ping MEthode : ICMP Ping

# Puis sauvegarder

```

## Règles iptables

```bash
# /sbin/iptables-fw.sh

cat > /sbin/iptables-fw.sh << EOF
#!/bin/bash
# iptables firewall

# iptables configuration
fw_start() {

    # Make sure NEW incoming tcp connections are SYN packets; otherwise we need to drop them:
    iptables -A INPUT -p tcp ! --syn -m state --state NEW -j DROP

    # Packets with incoming fragments drop them
    iptables -A INPUT -f -j DROP

    # Incoming malformed XMAS packets drop them:
    iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP


    # Incoming malformed NULL packets:
    iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP


    # DNS/DHCP lxc-net
    iptables -A INPUT -i lxcbr0 -p tcp -m tcp --dport 53 -j ACCEPT
    iptables -A INPUT -i lxcbr0 -p udp -m udp --dport 53 -j ACCEPT
    iptables -A INPUT -i lxcbr0 -p tcp -m tcp --dport 67 -j ACCEPT
    iptables -A INPUT -i lxcbr0 -p udp -m udp --dport 67 -j ACCEPT
    iptables -A FORWARD -o lxcbr0 -j ACCEPT
    iptables -A FORWARD -i lxcbr0 -j ACCEPT

    # localhost traffic
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT

    # Accepts all established inbound connections
    iptables -A INPUT   -m state --state ESTABLISHED,RELATED -j ACCEPT
    iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

    # Allows all outbound traffic:
    iptables -A OUTPUT -j ACCEPT

    # Allow all outbound traffic from Linux Containers:
    #iptables -A FORWARD -i lxcbr0 -j ACCEPT

    # Allow HTTP traffic (to be forwarded to the Linux Container hosting the server) :
    iptables -A INPUT   -i ens33 -p tcp --dport 80 -j ACCEPT
    iptables -A FORWARD -i ens33 -p tcp --dport 80 -j ACCEPT

    # Allow HTTPS traffic (to be forwarded to the Linux Container hosting the server) :
    iptables -A INPUT   -i ens33 -p tcp --dport 443 -j ACCEPT
    iptables -A FORWARD -i ens33 -p tcp --dport 443 -j ACCEPT

    # Allow FTP traffic (to be forwarded to the Linux Container hosting the server) :
    iptables -A INPUT   -i ens33 -p tcp --dport 2121 -j ACCEPT
    iptables -A FORWARD -i ens33 -p tcp --dport 2121 -j ACCEPT

    # Allows SSH to the host:
    iptables -A INPUT -p tcp -m state --state NEW --dport 2202 -j ACCEPT

    # Allows HTTP 8000 to the host:
    iptables -A INPUT -p tcp -m state --state NEW --dport 8000 -j ACCEPT

    # Allow ping
    iptables -A INPUT -p icmp -m icmp --icmp-type 8 -j ACCEPT

    # log iptables denied calls (access via 'dmesg' command)
    iptables -A INPUT   -m limit --limit 5/min -j LOG --log-prefix "iptables INPUT denied: " --log-level 7
    iptables -A OUTPUT  -m limit --limit 5/min -j LOG --log-prefix "iptables OUTPUT denied: " --log-level 7
    iptables -A FORWARD -m limit --limit 5/min -j LOG --log-prefix "iptables FORWARD denied: " --log-level 7

    # Reject all other inbound - default deny unless explicitly allowed policy:
    iptables -A INPUT   -j REJECT
    iptables -A FORWARD -j REJECT

    # Forward HTTP traffic to the Linux Container running it:
    iptables -t nat -A PREROUTING  -i ens33 -p tcp -m tcp --dport 80 -j DNAT --to-destination 10.0.10.2:80
    # Forward HTTPS traffic to the Linux Container running it:
    iptables -t nat -A PREROUTING  -i ens33 -p tcp -m tcp --dport 443 -j DNAT --to-destination 10.0.10.2:443
    # Forward FTP traffic to the Linux Container running it:
    iptables -t nat -A PREROUTING  -i ens33 -p tcp -m tcp --dport 2121 -j DNAT --to-destination 10.0.10.2:2121

    # Allow LXC subnet net access.
    iptables -t nat -A POSTROUTING -s 10.0.10.0/24 -j MASQUERADE
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
case "\$1" in
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

EOF


# /etc/systemd/system/iptables-fw.service
cat > /etc/systemd/system/iptables-fw.service << EOF
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
EOF

chmod 755 /sbin/iptables-fw.sh
systemctl enable iptables-fw
systemctl start iptables-fw


```


## Clean tout à la fin

### Alpine

```bash
# disable mysql history
ln -sf /dev/null /root/.mysql_history

# disable ash history
echo "*    *    *    *    *    rm -f /root/.ash_history" >> /etc/crontabs/root
rc-service crond restart
#echo "export CONFIG_FEATURE_EDITING_SAVEHISTORY=n" >> /etc/profile

# change mdp root (default any mdp)
printf "mdp_root_not_weak\nmdp_root_not_weak\n" | passwd root

# cron auto delete
rm /root/.ash_history
rm /root/.mysql_history
rm /root/.wget-hsts

# auto update security
apk add apk-cron # créer un script dans /etc/periodic/daily/apk qui run un upgrade

```

### Debian

```bash
# disable bash history
echo 'set +o history' >> /root/.bashrc
echo 'set +o history' >> /home/peterpan/.bashrc

# disable mysql history
echo 'export MYSQL_HISTFILE=/dev/null' >> /root/.bashrc
echo 'export MYSQL_HISTFILE=/dev/null' >> /home/peterpan/.bashrc


# delete history
rm /root/.bash_history & rm /home/peterpan/.bash_history
rm /root/.mysql_history & rm /home/peterpan/.mysql_history

apt --purge autoremove

# auto update security, 0 update, 5 upgrade juste security
apt install cron-apt

echo 'upgrade -o quiet=1 -o APT::Get::List-Cleanup=false -o Dir::Etc::SourceList=/etc/apt/sources.list.d/security.list -o Dir::Etc::SourceParts=\"/dev/null\""' > /etc/cron-apt/action.d/5-security

```


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
