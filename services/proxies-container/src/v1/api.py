import os, time, subprocess, signal

def clear():
    os.system("clear")

def writefirewallfile(proxyip, proxyport, fivemip, loadbalancer):
    firewall = open("/etc/DigitProtect/firewall.sh", "w")
    firewallstring = """    sudo iptables -F
    sudo iptables -t nat -F
    sudo iptables -t raw -F
    net.ipv4.ip_forward=1
    sudo ipset destroy
    sudo ipset flush
    sudo ipset create whitelist hash:net,port,net hashsize 32768 maxelem 99999999
    sudo ipset create sourceports hash:net,port,net hashsize 32768 maxelem 99999999
    sudo ipset create insrc hash:net,net hashsize 32768 maxelem 99999999
    sudo ipset create bypass hash:net hashsize 32768 maxelem 99999999
    sudo ipset add bypass REPLACE_BY_FIVEMIP
    sudo ipset add bypass REPLACE_BY_SECONDFIVEMIP
    sudo ipset add bypass REPLACE_BY_LOADBALANCER
    sudo iptables -t raw --new-chain WHITELIST
    sudo iptables -t raw --new-chain VALIDSRC
    sudo iptables -t raw --new-chain HTTP
    sudo iptables -t raw --new-chain NEWSRCPORT
    sudo iptables -t raw --new-chain INSRC

    sudo iptables -t raw -A PREROUTING -m set --match-set bypass src -j ACCEPT

    sudo iptables -t raw -A PREROUTING -p tcp -m tcp --dport REPLACE_BY_PROXYPORT -j DROP
    sudo iptables -t raw -A PREROUTING -p udp -m udp --dport REPLACE_BY_PROXYPORT -j DROP

    sudo iptables -t nat -A PREROUTING -m set --match-set whitelist src,dst,dst -p tcp -j REDIRECT --to-ports REPLACE_BY_PROXYPORT
    sudo iptables -t nat -A PREROUTING -m set --match-set whitelist src,dst,dst -p udp -j REDIRECT --to-ports REPLACE_BY_PROXYPORT

    sudo iptables -t raw -A PREROUTING -m set --match-set whitelist src,dst,dst -j WHITELIST

    sudo iptables -t raw -A WHITELIST -p tcp -j NEWSRCPORT 

    sudo iptables -t raw -A WHITELIST -m set --match-set insrc src,dst -j INSRC

    sudo iptables -t raw -A INSRC -m set --match-set sourceports src,src,dst -j VALIDSRC

    sudo iptables -t raw -A WHITELIST -p udp -m hashlimit --hashlimit-name conn_rate_limit --hashlimit-mode srcip,srcport --hashlimit-above 1/minute --hashlimit-burst 1 --hashlimit-htable-expire 60000 --hashlimit-htable-size 1024000 --hashlimit-htable-max 1048576 --hashlimit-htable-gcinterval 1000 -j NEWSRCPORT

    sudo iptables -t raw -A INSRC -p udp -m hashlimit --hashlimit-name conn_rate_limit_fdp --hashlimit-mode srcip,srcport --hashlimit-above 2/sec --hashlimit-burst 2 --hashlimit-htable-expire 60000  --hashlimit-htable-size 1024000 --hashlimit-htable-max 1048576 --hashlimit-htable-gcinterval 1000 -j NEWSRCPORT

    sudo iptables -t raw -A NEWSRCPORT -m hashlimit --hashlimit-name conn_rate_limit_pkts --hashlimit-mode srcip --hashlimit-above 300/sec --hashlimit-burst 500 --hashlimit-htable-expire 60000  --hashlimit-htable-size 1024000 --hashlimit-htable-max 1048576 --hashlimit-htable-gcinterval 1000 -j DROP

    sudo iptables -t raw -A NEWSRCPORT -j VALIDSRC

    sudo iptables -t raw -A VALIDSRC -p tcp -m string --algo kmp --string "GET /" -j HTTP
    sudo iptables -t raw -A VALIDSRC -p tcp -m string --algo kmp --string "POST /" -j HTTP

    sudo iptables -t raw -A VALIDSRC -j ACCEPT 

    sudo iptables -t raw -A HTTP -m string --algo bm --string "GET /players.json" -j DROP
    sudo iptables -t raw -A HTTP -m string --algo bm --string "GET /dynamic.json" -j DROP
    sudo iptables -t raw -A HTTP -m string --algo bm --string "GET /client" -j DROP

    sudo iptables -t raw -A HTTP -m hashlimit --hashlimit-name tcphttp1 --hashlimit-mode srcip,dstip --hashlimit-above 2/sec --hashlimit-burst 1 --hashlimit-htable-expire 60000 --hashlimit-htable-size 1024000 --hashlimit-htable-max 1048576 --hashlimit-htable-gcinterval 1000 -j DROP

    sudo iptables -t raw -A VALIDSRC -j DROP
    sudo iptables -t raw -A INSRC -j DROP
    sudo iptables -t raw -A NEWSRCPORT -j DROP
    sudo iptables -t raw -A WHITELIST -j DROP
    sudo iptables -t raw -P PREROUTING DROP"""
    firewallstring = firewallstring.replace("REPLACE_BY_PROXYIP", proxyip)
    firewallstring = firewallstring.replace("REPLACE_BY_PROXYPORT", proxyport)
    firewallstring = firewallstring.replace("REPLACE_BY_LOADBALANCER", loadbalancer)
    firewallstring = firewallstring.replace("REPLACE_BY_FIVEMIP", fivemip)
    firewallstring = firewallstring.replace("REPLACE_BY_SECONDFIVEMIP", "SECOND_FIVEM_IP")
    firewall.write(firewallstring)
    os.system("sudo bash /etc/DigitProtect/firewall.sh")

def writenginxfile(connectport, proxyip, proxyport, fivemip, fivemport, domainname, loadbalancer):
    nginxconf = open("/etc/nginx/nginx.conf", "w")
    nginxconfstring = """user www-data;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;

stream {
    server {
        listen     REPLACE_BY_PROXYPORT udp reuseport;
        proxy_pass REPLACE_BY_FIVEMIP:REPLACE_BY_FIVEMPORT;
    }
    server {
        listen     REPLACE_BY_PROXYPORT;
        proxy_pass REPLACE_BY_FIVEMIP:REPLACE_BY_FIVEMPORT;
    }
}

events {
	worker_connections 768;
}


http {

	sendfile on;
	tcp_nopush on;
	types_hash_max_size 2048;

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
    listen     REPLACE_BY_CONNECTPORT;

    server_name REPLACE_BY_DOMAINNAME;

    location / {
        
set_real_ip_from REPLACE_BY_LOADBALANCER;

        # - IPv4
set_real_ip_from 173.245.48.0/20;
set_real_ip_from 103.21.244.0/22;
set_real_ip_from 103.22.200.0/22;
set_real_ip_from 103.31.4.0/22;
set_real_ip_from 141.101.64.0/18;
set_real_ip_from 108.162.192.0/18;
set_real_ip_from 190.93.240.0/20;
set_real_ip_from 188.114.96.0/20;
set_real_ip_from 197.234.240.0/22;
set_real_ip_from 198.41.128.0/17;
set_real_ip_from 162.158.0.0/15;
set_real_ip_from 104.16.0.0/13;
set_real_ip_from 104.24.0.0/14;
set_real_ip_from 172.64.0.0/13;
set_real_ip_from 131.0.72.0/22;

# - IPv6
set_real_ip_from 2400:cb00::/32;
set_real_ip_from 2606:4700::/32;
set_real_ip_from 2803:f800::/32;
set_real_ip_from 2405:b500::/32;
set_real_ip_from 2405:8100::/32;
set_real_ip_from 2a06:98c0::/29;
set_real_ip_from 2c0f:f248::/32;

real_ip_header LB-Real-IP;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $remote_addr;
        # required to pass auth headers correctly
        proxy_pass_request_headers on;
        # required to not make deferrals close the connection instantly
        proxy_http_version 1.1;
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

os.system("bash /etc/DigitProtect/firewall.sh")


app = Flask(__name__)
api = Api(app)
key_valid = "SECRET_KEY_HERE"
set_string = "set"
drop_string = "drop"
setup_string = "setup"
pid = ""


test = {

}


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
                        cmd = ["/etc/DigitProtect/main", "-port", port, "-ip", ip, "-dst", proxyip, "-iface", "ens18"]
                        process = subprocess.Popen(cmd)
                        if proxyip not in test:
                            test[proxyip] = {}
                        test[proxyip][port] = str(process.pid)
                        os.system("ipset add whitelist " + ip + ",tcp:" + port + "," + proxyip)
                        os.system("ipset add whitelist " + ip + ",udp:" + port + "," + proxyip)
        
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
                            if proxyip not in test:
                                test[proxyip] = {}
                            porttodrop = test[proxyip][port]
                            try:
                                os.system("kill -9 " + str(porttodrop))
                            except:
                                print("No pid")

                            os.system("ipset del whitelist " + ip + ",tcp:" + port + "," + proxyip)
                            os.system("ipset del whitelist " + ip + ",udp:" + port + "," + proxyip)

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
            
            # Recuperer les pid dans le dictionnaire et les kill

            for datastore in test:
                try:
                    os.system("kill -9 " + str(test[datastore]))
                except:
                    print("No pid")


            connectport = request.args.get("connectport")
            proxyip = request.args.get("proxyip")
            proxyport = request.args.get("proxyport")
            fivemip = request.args.get("fivemip")
            fivemport = request.args.get("fivemport")
            domainname = request.args.get("domainname")
            loadbalancing = request.args.get("loadbalancing")
            if connectport != None and proxyip != None and proxyport != None and fivemip != None and fivemport != None and domainname != None and loadbalancing != None: 
                writenginxfile(connectport, proxyip, proxyport, fivemip, fivemport, domainname, loadbalancing)
                writefirewallfile(proxyip, proxyport, fivemip, loadbalancing)
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