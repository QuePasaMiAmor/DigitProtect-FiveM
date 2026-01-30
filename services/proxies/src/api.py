import os, time, subprocess, signal

def clear():
    os.system("clear")

def writefirewallfile(proxyip, proxyport, connectport, fivemip, loadbalancer):
    firewall = open("/etc/DigitProtect/firewall.sh", "w")
    firewallstring = """
    sudo ipset destroy
    sudo ipset flush
    sudo ipset create whitelist hash:net,net hashsize 32768 maxelem 99999999 timeout 120
    sudo ipset create redirect_http hash:net,net hashsize 32768 maxelem 99999999 timeout 10
    sudo ipset create info_json_http hash:net hashsize 32768 maxelem 99999999 timeout 10
    sudo iptables -t nat -F
    sudo iptables -t raw -F
    sudo iptables -t raw --new-chain INFOJSON
    sudo iptables -t raw --new-chain SECONDINFO
    """
    firewallstring = firewallstring.replace("REPLACE_BY_PROXYIP", proxyip)
    firewallstring = firewallstring.replace("REPLACE_BY_PROXYPORT", proxyport)
    firewallstring = firewallstring.replace("REPLACE_BY_HTTPPORT", connectport)
    firewallstring = firewallstring.replace("REPLACE_BY_LOADBALANCER", loadbalancer)
    firewallstring = firewallstring.replace("REPLACE_BY_FIVEMIP", fivemip)
    firewallstring = firewallstring.replace("REPLACE_BY_SECONDFIVEMIP", "SECOND_FIVEM_IP")
    firewall.write(firewallstring)
    os.system("sudo bash /etc/DigitProtect/firewall.sh")


def writenginxfile(connectport, proxyip, proxyport, fivemip, fivemport, domainname, loadbalancer):
    nginxconf = open("/etc/nginx/nginx.conf", "w")
    nginxconfstring = """user www-data;
worker_processes 64;
worker_rlimit_nofile 999999;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;

stream {
    server {
        listen     REPLACE_BY_PROXYPORT udp reuseport;
        proxy_bind VOXILITY_INTERNAL;
        proxy_pass REPLACE_BY_FIVEMIP:REPLACE_BY_FIVEMPORT;
    }
}

events {
    worker_connections 64000;
    use epoll;
    multi_accept on;
}


http {

	sendfile on;
	tcp_nopush on;
	types_hash_max_size 2048;

    limit_req_zone $binary_remote_addr zone=flood:10m rate=3r/s; 
    proxy_cache_path /srv/cachefivem levels=1:2 keys_zone=fivem:48m max_size=20g inactive=2h;


	include /etc/nginx/mime.types;
	default_type application/octet-stream;

	ssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3; # Dropping SSLv3, ref: POODLE
	ssl_prefer_server_ciphers on;

	access_log /var/log/nginx/access.log;
	error_log /var/log/nginx/error.log;

	gzip on;

    upstream backend {
        server REPLACE_BY_FIVEMIP:REPLACE_BY_FIVEMPORT;
    }
    
    server {
    listen     REPLACE_BY_PROXYPORT;

    server_name REPLACE_BY_DOMAINNAME;

    location /client {
        if ($request_method != POST ) {
            return 444;
        }
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $remote_addr;
        # required to pass auth headers correctly
        proxy_pass_request_headers on;
        # required to not make deferrals close the connection instantly
        proxy_http_version 1.1;
        limit_req zone=flood burst=2 nodelay;
        proxy_bind VOXILITY_INTERNAL;
        proxy_pass http://backend;
    }

    location / {
        if ($request_method != GET ) {
            return 444;
        }
        if ($http_user_agent !~* (CitizenFX/1)) {
            return 403;
        }
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $remote_addr;
        # required to pass auth headers correctly
        proxy_pass_request_headers on;
        # required to not make deferrals close the connection instantly
        proxy_http_version 1.1;
        proxy_cache_lock on;
        proxy_cache fivem;
        proxy_cache_valid 1y;
        proxy_cache_key $request_uri$is_args$args;
        proxy_cache_revalidate on;
        proxy_cache_min_uses 1;
        limit_req zone=flood burst=5 nodelay;
        proxy_bind VOXILITY_INTERNAL;
        proxy_pass http://backend;
    }

}
}
"""
    nginxconfstring = nginxconfstring.replace("REPLACE_BY_CONNECTPORT", connectport)
    nginxconfstring = nginxconfstring.replace("REPLACE_BY_PROXYPORT", proxyport)
    nginxconfstring = nginxconfstring.replace("REPLACE_BY_PROXYIP", proxyip)
    nginxconfstring = nginxconfstring.replace("REPLACE_BY_LOADBALANCER", loadbalancer)
    nginxconfstring = nginxconfstring.replace("REPLACE_BY_FIVEMIP", fivemip)
    nginxconfstring = nginxconfstring.replace("REPLACE_BY_FIVEMPORT", fivemport)
    nginxconfstring = nginxconfstring.replace("REPLACE_BY_DOMAINNAME", domainname)
    nginxconf.write(nginxconfstring)


from flask import Flask, request
from flask_restful import Api

clear()

app = Flask(__name__)
api = Api(app)
key_valid = "SIKfkqsjdz415"
set_string = "set"
drop_string = "drop"
setup_string = "setup"
pid = ""


test = {

}

os.system("ip r add 5.254.17.0/28 dev ens19 src VOXILITY_INTERNAL table voxilityUnprotected")

os.system("ip r add default via 5.254.17.1 dev ens19 table voxilityUnprotected")

os.system("ip rule add from VOXILITY_INTERNAL/32 table voxilityUnprotected")

os.system("ip rule add to VOXILITY_INTERNAL/32 table voxilityUnprotected")


## launch command ##


@app.route('/', methods=['GET', 'POST'])
def index():
    ip_request = request.remote_addr
    print(ip_request)

    key = request.args.get("key")
    if str(key) == key_valid:

        action = request.args.get("action")
        
        if action == set_string:
            ip = request.args.get("ip")
            if ip != None:
                port = request.args.get("port")
                if port != None:
                    proxyip = request.args.get("proxyip")
                    if proxyip != None:
                        fresponse = 'true'
                        os.system("ipset add whitelist " + ip + "," + proxyip)
        
                        return fresponse
                    else:
                        return f"<h1>Good action but no proxy ip set</h1>"
                else:
                    return f"<h1>Good action but no ports set</h1>"
            else:
                return f"<h1>Good action but no ip set</h1>"

        elif action == drop_string:
            ip = request.args.get("ip")
            if ip != None:
                port = request.args.get("port")
                if port != None:
                    proxyip = request.args.get("proxyip")
                    if proxyip != None:
                        fresponse = 'false'
                        try:
                            os.system("ipset del whitelist " + ip + "," + proxyip)

                            fresponse = 'true'
                        except:
                            fresponse = 'false'

                        return fresponse
                    else:
                        return f"<h1>Good action but no proxy ip set</h1>"
                else:
                    return f"<h1>Good action but no port set</h1>"
            else:
                return f"<h1>Good action but no ip set</h1>"

        elif action == setup_string:

            connectport = request.args.get("connectport")
            proxyip = request.args.get("proxyip")
            proxyport = request.args.get("proxyport")
            fivemip = request.args.get("fivemip")
            fivemport = request.args.get("fivemport")
            domainname = request.args.get("domainname")
            loadbalancing = request.args.get("loadbalancing")
            if connectport != None and proxyip != None and proxyport != None and fivemip != None and fivemport != None and domainname != None and loadbalancing != None: 
                writenginxfile(connectport, proxyip, proxyport, fivemip, fivemport, domainname, loadbalancing)
                writefirewallfile(proxyip, proxyport, connectport, fivemip, loadbalancing)
                os.system("sudo bash /etc/DigitProtect/firewall.sh")
                os.system("service nginx reload")
                return "true" 
            else:
                return "false"
        else:    
            return "<h1>Good Key but not action set</h1>"
        

    else:
        return '<h1>En maintenance</h1><img src="https://image.noelshack.com/fichiers/2018/22/3/1527639157-dfqsf.png" alt="alternatetext">'

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=40321,debug=True)