

3. Install Python Dependencies

pip3 install --upgrade pip
\\

#Fixes up the later installed paramiko
sudo apt-get install libffi-dev  

 ```shell
 python3 -m pip install -r requirements.txt
 ```

 apt install bgpq3


 root@portal:/etc/bird# bgpq4 -4 -J -l prefixes AS6556
policy-options {
replace:
 prefix-list prefixes {
    44.31.46.0/23;
    44.31.46.0/24;
    44.31.47.0/24;
    44.190.40.0/24;
    44.190.41.0/24;
    66.248.232.0/24;

    
    66.248.233.0/24;
    208.104.171.0/24;
 }
}


bgpq4 -4b -A -p AS6556


INSTALL NODEJS
sudo apt update
sudo apt upgrade

sudo apt install curl
curl -fsSL https://deb.nodesource.com/setup_16.x | sudo -E bash -

sudo apt install npm

curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.2/install.sh | bash
sudo npm install -g npm@8.19.2   

sudo npm install -D tailwindscss

npx tailwindcss int


npx tailwindcss -i ./assets/input.css ./assets/output.css --watch


# Uninstall icmplib
pip3 uninstall icmplib

# Download and extract this repository
wget -qO- https://github.com/ValentinBELYN/icmplib/archive/master.tar.gz | tar -xzf -
cd icmplib-master

# Install the version under development:
python3 setup.py install


sudo setcap cap_net_raw+ep /bin/ping
ls -l $(which ping)


# ALLOW PYThON TO OPEN raw sockets.  <____SANITISE EVERYTHING!!!!!!!!
sudo setcap 'CAP_NET_RAW+eip' /usr/bin/python3.7


# INSTALL ARP-SCAN
sudo apt install arp-scan

#INSTALL NGINX Reverse Proxy
sudo apt install nginx -y
pip3 install pyOpenSSL --upgrade    #Gets odd error after installing Nginx, this fixes.
apt remove python3-requests         #fix ModuleNotFoundError: No module named 'requests'
apt install python3-requests


python3 -m pip install --upgrade pip setuptools wheel

sudo pip3 install -U pip
pip3 install -U pip setuptools
sudo python3 -m easy_install --upgrade pyOpenSSL    #Fixes

sudo mkdir -p /usr/share/nginx/.well-known/acme-challenge
sudo chown -R www-data:www-data /usr/share/nginx


nano /etc/nginx/sites-available/default


#EDIT NGINX CONFIG
server {
        listen 80 default_server;
        listen [::]:80 default_server;

        server_name testbox.44net.cloud;
        root /var/www/html;

        # Add index.php to the list if you are using PHP
        index index.html index.htm index.nginx-debian.html;

        location ^~ /.well-known/acme-challenge/ { root /usr/share/nginx/html ; }
        location / { return 301 https://testbox.44net.cloud$request_uri; }
}

server {
        # SSL configuration
        listen 443 ssl default_server;
        listen [::]:443 ssl default_server;

        server_name testbox.44net.cloud;
        root /var/www/html;

        # Add index.php to the list if you are using PHP
        index index.html index.htm index.nginx-debian.html;

        ssl_certificate /etc/letsencrypt/live/testbox.44net.cloud/fullchain.pem;
        ssl_certificate_key /etc/letsencrypt/live/testbox.44net.cloud/privkey.pem;
        ssl_trusted_certificate /etc/letsencrypt/live/testbox.44net.cloud/chain.pem;
        ssl_stapling on;
        ssl_stapling_verify on;


        location / {
                # First attempt to serve request as file, then  as directory, then fall back to displaying a 404.
                try_files $uri $uri/ =404;
        }

        location /api/v1/ {
                proxy_pass http://66.248.232.167:5000/;
                proxy_buffering off;
                proxy_set_header X-Real-IP $remote_addr;
                proxy_set_header X-Forwarded-Host $host;
                proxy_set_header X-Forwarded-Port $server_port;
        }



                # GIVES https://subfolder.44net.cloud
                location ^~ /subfolder/ {
                proxy_pass http://subfolder.domain.com;
                proxy_set_header X-Real-IP $remote_addr;
                proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
                proxy_set_header X-Forwarded-Proto $scheme;
                }


        # deny access to .htaccess files, if Apache's document root concurs with nginx's one
        location ~ /\.ht {
                deny all;
        }
}







}


#INSTALL Lets Encrypt
  sudo apt install software-properties-common
  sudo apt update
  sudo apt install certbot


  sudo certbot certonly --expand --webroot -w /usr/share/nginx/html -d testbox.44net.cloud



#FIND PYTHON CERT
python3
>>> import certifi
>>> certifi.where()
'/etc/ssl/certs/ca-certificates.crt'

#CONVERT cert TO PEM
sudo openssl x509 -in /etc/ssl/certs/ca-certificates.crt -inform DER -outform PEM -out /usr/share/nginx/ca-certificates.pem
# exverto
# exverto
