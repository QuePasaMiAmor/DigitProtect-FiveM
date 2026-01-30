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
    sudo ipset create whitelist hash:net,port,net hashsize 32768 maxelem 99999999 timeout 1200
    sudo ipset create connecting hash:net,port,net hashsize 32768 maxelem 99999999 timeout 1200
    sudo ipset create sourceports hash:net,port,net hashsize 32768 maxelem 99999999 timeout 30
    sudo ipset create bypass hash:net hashsize 32768 maxelem 99999999
    sudo ipset create fivemlist hash:net hashsize 32768 maxelem 99999999
    sudo ipset create first_getinfo_drop hash:ip,port,ip hashsize 256000 maxelem 99999999 timeout 3
    sudo ipset create first_getinfo_accept hash:ip,port,ip hashsize 256000 maxelem 9999999 timeout 7
    sudo ipset create first_length_80 hash:ip,port,ip hashsize 256000 maxelem 9999999 timeout 3
    sudo ipset create first_length_116 hash:ip,port,ip hashsize 256000 maxelem 9999999 timeout 3
    sudo ipset add bypass REPLACE_BY_FIVEMIP
    sudo ipset add bypass REPLACE_BY_SECONDFIVEMIP
    sudo ipset add bypass REPLACE_BY_LOADBALANCER
    sudo ipset add bypass VOXILITY_INTERNAL
    sudo ipset add bypass VOXILITY_INTERNAL_2
    sudo ipset add fivemlist 176.31.236.143 
    sudo ipset add fivemlist 5.135.143.71 
    sudo ipset add fivemlist 178.33.224.212
    sudo iptables -t raw --new-chain WHITELIST
    sudo iptables -t raw --new-chain HTTP
    sudo iptables -t raw --new-chain TCP
    sudo iptables -t raw --new-chain UDP
    sudo iptables -t raw --new-chain GOOD
    sudo iptables -t raw --new-chain KEEPWL
    sudo iptables -t raw --new-chain TCPWL
    sudo iptables -t raw --new-chain CONNECTING

    iptables -t raw -A PREROUTING -p tcp -m tcp --syn -j CT --notrack 

    iptables -A INPUT -p tcp -m tcp -m conntrack --ctstate INVALID,UNTRACKED -j SYNPROXY --sack-perm --timestamp --wscale 7 --mss 1460 

    iptables -A INPUT -m conntrack --ctstate INVALID -j DROP

    sudo iptables -t raw -A PREROUTING -m set --match-set bypass src -j ACCEPT

    sudo iptables -t raw -A PREROUTING -p tcp -m set --match-set fivemlist src -j ACCEPT

    sudo iptables -t raw -A PREROUTING -m set --match-set whitelist src,dst,dst -j WHITELIST

    sudo iptables -t raw -A PREROUTING -p tcp --dport 30120 -j TCP

    sudo iptables -t raw -A WHITELIST -p tcp -j TCPWL 

    sudo iptables -t raw -A TCPWL -p tcp -j SET --add-set whitelist src,dst,dst --exist --timeout 1200

    sudo iptables -t raw -A TCPWL -j TCP

    sudo iptables -t raw -A WHITELIST -p udp -j UDP

    sudo iptables -t raw -A UDP -m set --match-set sourceports src,src,dst -j GOOD

    sudo iptables -t raw -A GOOD -m hashlimit --hashlimit-name hashlimit_udp_srcports --hashlimit-mode srcip,srcport,dstip,dstport --hashlimit-above 10000/sec --hashlimit-burst 5 --hashlimit-htable-expire 30000  --hashlimit-htable-size 1024000 --hashlimit-htable-max 1048576 --hashlimit-htable-gcinterval 1000 -j DROP

    sudo iptables -t raw -A GOOD -p udp -j SET --add-set sourceports src,src,dst --exist --timeout 30

    sudo iptables -t raw -A GOOD -j KEEPWL

    sudo iptables -t raw -A UDP -m set --match-set connecting src,dst,dst -j CONNECTING

    sudo iptables -t raw -A CONNECTING -m string --hex-string "|67 65 74 69 6e 66 6f|" --algo bm -m set --match-set first_getinfo_drop src,src,dst -j DROP

    sudo iptables -t raw -A CONNECTING -m string --hex-string "|67 65 74 69 6e 66 6f|" --algo bm -m set --match-set first_getinfo_accept src,src,dst -j SET --add-set first_length_80 src,src,dst
    sudo iptables -t raw -A CONNECTING -m string --hex-string "|67 65 74 69 6e 66 6f|" --algo bm -m set --match-set first_getinfo_accept src,src,dst -j KEEPWL

    sudo iptables -t raw -A CONNECTING -m string --hex-string "|67 65 74 69 6e 66 6f|" --algo bm -j SET --add-set first_getinfo_drop src,src,dst
    sudo iptables -t raw -A CONNECTING -m string --hex-string "|67 65 74 69 6e 66 6f|" --algo bm -j SET --add-set first_getinfo_accept src,src,dst

    sudo iptables -t raw -A CONNECTING -m length --length 80 -m set --match-set first_length_80 src,src,dst -j SET --add-set first_length_116 src,src,dst
    sudo iptables -t raw -A CONNECTING -m length --length 80 -m set --match-set first_length_80 src,src,dst -j KEEPWL

    sudo iptables -t raw -A CONNECTING -m length --length 116 -m set --match-set first_length_116 src,src,dst -j SET --add-set sourceports src,src,dst

    sudo iptables -t raw -A CONNECTING -j DROP

    sudo iptables -t raw -A TCP -m hashlimit --hashlimit-name conn_rate_limit_pkts --hashlimit-mode srcip,dstip,dstport --hashlimit-above 300/sec --hashlimit-burst 500 --hashlimit-htable-expire 60000  --hashlimit-htable-size 1024000 --hashlimit-htable-max 1048576 --hashlimit-htable-gcinterval 1000 -j DROP

    sudo iptables -t raw -A TCP -m string --algo kmp --string "GET /" -j HTTP
    sudo iptables -t raw -A TCP -m string --algo kmp --string "POST /" -j HTTP

    sudo iptables -t raw -A TCP -j ACCEPT 

    sudo iptables -t raw -A HTTP -m string --algo bm --string "GET /players.json" -j DROP
    sudo iptables -t raw -A HTTP -m string --algo bm --string "GET /dynamic.json" -j DROP
    sudo iptables -t raw -A HTTP -m string --algo bm --string "GET /client" -j DROP

    sudo iptables -t raw -A HTTP -m hashlimit --hashlimit-name tcphttp1 --hashlimit-mode srcip,dstip,dstport --hashlimit-above 2/sec --hashlimit-burst 1 --hashlimit-htable-expire 60000 --hashlimit-htable-size 1024000 --hashlimit-htable-max 1048576 --hashlimit-htable-gcinterval 1000 -j DROP

    sudo iptables -A INPUT -p udp -m hashlimit --hashlimit-name hashlimit_udp_srcports_filter --hashlimit-mode srcip,srcport,dstip,dstport --hashlimit-above 10000/sec --hashlimit-burst 5 --hashlimit-htable-expire 30000  --hashlimit-htable-size 1024000 --hashlimit-htable-max 1048576 --hashlimit-htable-gcinterval 1000 -j DROP

    sudo iptables -t raw -A KEEPWL -p udp -j SET --add-set whitelist src,dst,dst --exist --timeout 1200

    sudo iptables -t raw -A KEEPWL -j ACCEPT
    sudo iptables -t raw -A UDP -j DROP
    sudo iptables -t raw -A WHITELIST -j DROP
    sudo iptables -t raw -P PREROUTING DROP"""
    firewallstring = firewallstring.replace("REPLACE_BY_PROXYIP", proxyip)
    firewallstring = firewallstring.replace("REPLACE_BY_PROXYPORT", proxyport)
    firewallstring = firewallstring.replace("REPLACE_BY_LOADBALANCER", loadbalancer)
    firewallstring = firewallstring.replace("REPLACE_BY_FIVEMIP", fivemip)
    firewallstring = firewallstring.replace("REPLACE_BY_SECONDFIVEMIP", "SECOND_FIVEM_IP")
    firewall.write(firewallstring)
    os.system("sudo bash /etc/DigitProtect/firewall.sh")


from flask import Flask, request
from flask_restful import Api

clear()

#os.system("bash /etc/DigitProtect/firewall.sh")


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
                        os.system("ipset add whitelist " + ip + ",tcp:" + port + "," + proxyip)
                        os.system("ipset add whitelist " + ip + ",udp:" + port + "," + proxyip)
                        os.system("ipset add connecting " + ip + ",udp:" + port + "," + proxyip)

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

            connectport = request.args.get("connectport")
            proxyip = request.args.get("proxyip")
            proxyport = request.args.get("proxyport")
            fivemip = request.args.get("fivemip")
            fivemport = request.args.get("fivemport")
            domainname = request.args.get("domainname")
            loadbalancing = request.args.get("loadbalancing")
            if connectport != None and proxyip != None and proxyport != None and fivemip != None and fivemport != None and domainname != None and loadbalancing != None: 
                writefirewallfile(proxyip, proxyport, fivemip, loadbalancing)
                os.system("sudo bash /etc/DigitProtect/firewall.sh")
                return "true" 
            else:
                return "false"
        else:    
            return "<h1>Good Key but not action set</h1>"
        

    else:
        return '<h1>En maintenance</h1><img src="https://image.noelshack.com/fichiers/2018/22/3/1527639157-dfqsf.png" alt="alternatetext">'

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=40321,debug=True)