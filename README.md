# DigitProtect - Innovative FiveM Anti-DDoS & Anti-IP Spoofing Solution

DigitProtect is a high-performance, multi-layered DDoS protection system designed specifically for FiveM servers. Originally developed and used in 2023, it leverages reverse proxies and deep packet inspection (DPI) on the Voxility network (70 Tb/s capacity) to protect game servers from volumetric attacks and sophisticated IP spoofing.

## 🚀 Key Features

*   **Multi-Layered Defense**: Combines Nginx reverse proxying, `iptables` raw table filtering, and `ipset` kernel-level whitelisting.
*   **Anti-IP Spoofing**: Uses a custom Go-based DPI engine to validate player source ports in real-time.
*   **Automated Whitelisting**: Seamlessly integrates with FiveM's `playerConnecting` event to authorize players before they even reach the server.
*   **Dynamic Port Generation**: Randomizes ports for each connection to make targeting individual sessions harder.
*   **Voxility Integration**: Designed to be deployed on networks with high-capacity DDoS mitigation like Voxility.
*   **Zero-Touch Configuration**: Each API component automatically generates its own optimized Nginx configuration and firewall rules upon setup, ensuring consistent deployment across multiple nodes.

---

## 🏗 Architecture Overview

The system consists of four main components working in tandem:

1.  **FiveM Resource**: The "Brain" and **Central Orchestrator**. Runs on your game server, detects connections, and manages the entire network's configuration. It pushes dynamic setup instructions to all proxies and protection layers.
2.  **Protection Layer (v1 & v2)**: The "Shield". A high-performance machine (e.g., on Voxility) that performs the heavy lifting of DPI and IP spoofing protection.
    *   **v1**: Uses a Go-based raw socket listener to learn player source ports.
    *   **v2**: Uses advanced `iptables` string matching (`getinfo` hex pattern) and packet length validation for a more integrated approach.
3.  **Edge Proxies**: The "Sentinels". Distributed nodes that handle initial traffic reception and forwarding using Nginx and `ipset`.
4.  **Load Balancer & Anti-Scrap**: Manages HTTP traffic and protects the `/client` endpoint from scraping and rapid endpoint requests using `antiscrap.py`.

### Automated Orchestration
The FiveM resource acts as the central command center for the entire infrastructure. It doesn't just whitelist players; it actively manages the configuration of every node:
*   **Edge Proxy Configuration**: Automatically pushes Nginx upstream settings and initialization firewall rules to every node in your proxy network.
*   **Protection Layer Setup**: Remotely initializes the DPI engine and complex `iptables` raw table chains on the high-capacity protection machine.
*   **Load Balancer Synchronization**: Dynamically updates the load balancer's Nginx configuration to include the latest active proxy endpoints.
*   **Zero-Touch Deployment**: Once the individual APIs are running on your servers, the FiveM resource handles all the complex networking and security configuration automatically.

### The Connection Flow

1.  **Player Joins**: The player attempts to connect to the server.
2.  **Detection**: The FiveM resource catches the `playerConnecting` event.
3.  **Orchestration**:
    *   It sends a request to the **Protection Layer** to open a temporary "window" for the player's IP.
    *   It sends a request to the **Edge Proxy** to whitelist the player.
    *   It updates the server's `sv_endpoints` to point to the designated proxy.
4.  **Validation (Anti-IP Spoofing)**:
    *   **v1 (Go DPI Engine)**: A custom Go-based raw socket listener (`AF_PACKET`) monitors traffic at the Ethernet level. It captures the player's first UDP packets, identifies the unique source ports used by the CitizenFX client, and adds them to a kernel `ipset`.
    *   **v2 (Iptables DPI)**: Uses `iptables` string matching to detect the `getinfo` hex pattern and validates specific packet lengths (80 and 116 bytes) common to the FiveM handshake before whitelisting the source port.
    *   Any packet from that IP using a non-validated source port is dropped, effectively neutralizing IP spoofing attacks.
5.  **Access Granted**: Once validated, traffic is forwarded through the proxy chain to the game server.

---

## 🛠 Installation Guide

All components (Edge Proxies, Protection Machine, Load Balancer) feature an automated setup process. Once the API is running, the FiveM resource triggers a `setup` action that remotely configures Nginx, `iptables`, and `ipset` with the correct parameters (ports, IPs, and domain names).

### 1. Edge Proxy Nodes (`services/proxies`)
Deploy these on your edge VPS nodes.

1.  Install dependencies:
    ```bash
    sudo apt update && sudo apt install -y nginx ipset python3-flask python3-flask-restful
    ```
2.  Copy `services/proxies/src/api.py` to `/etc/DigitProtect/api.py`.
3.  Set your `key_valid` in `api.py`.
4.  Use `docs/api.service.example` to create a systemd service.
5.  `sudo systemctl enable --now digitprotect-api`.

### 2. Protection Machine (`services/proxies-container`)
Deploy this on your main protection machine (e.g., Voxility).

**For v1 (Go-based):**
1.  Compile Go engine: `go build -o main main.go` in `src/v1`.
2.  Move `main` and `api.py` to `/etc/DigitProtect/`.
3.  Ensure `ipset` is installed.

**For v2 (Iptables-based):**
1.  Move `src/v2/api.py` to `/etc/DigitProtect/`.
2.  This version handles all logic via `iptables` rules generated by the API.

### 3. Load Balancer & Anti-Scrap (`services/loadbalancer`)
1.  Run `api.py` for Nginx configuration management.
2.  Run `antiscrap.py` on port 61012 to filter `/client` requests.
3.  Nginx should be configured to proxy `/client` to `antiscrap.py`.

### 4. FiveM Server Resource (`services/fivem-resource`)
1.  Copy the `fivem-resource` folder to your server's `resources` directory.
2.  Edit `main.lua` and fill in the configuration:
    *   `ApiKey`: Must match the key set in your Proxy/Protection Machine APIs.
    *   `ProxyList`: List of your Edge Proxy IPs.
    *   `LoadBalancer`: IP of your Load Balancer.
    *   `ProxMox`: IP of your Protection Machine (Container Host).
    *   `FivemIP`: Your actual FiveM server's backend IP.
3.  Add `ensure fivem-resource` to your `server.cfg`.
4.  Apply the settings from `docs/server.cfg.example` to your `server.cfg`.

> **Note**: Upon the first resource start (and via the `RegeneratePorts` function), the resource will automatically call the `setup` action on all configured APIs to generate Nginx configurations and initialize firewall rules.

---

## ⚙️ Configuration Reference

### `server.cfg` Important Settings
```bash
# Force the server to report the proxy IP to the FiveM master list
sv_listingIPOverride "https://your.domain.com:443/"
sv_listingHostOverride "your.domain.com:443"

# Protect endpoint privacy
sv_endpointprivacy true

# Allow traffic from proxies
set sv_proxyIPRanges "PROXY_IP_1/32 PROXY_IP_2/32"
```

---

## 🔧 Customization & Troubleshooting

### Network Interfaces
The DPI engine and Iptables rules often target specific network interfaces (e.g., `ens18`, `ens19`, `eth0`).
*   **v1 (Go)**: Check `api.py` for the `-iface` flag in the `subprocess.Popen` call.
*   **v2 (Iptables)**: Ensure the interface names in the generated `firewall.sh` match your system (`ip link show`).

### API Keys
Security is managed via simple API keys. Ensure `key_valid` in all `api.py` files matches the `ApiKey` in the FiveM resource's `main.lua`.

### Domain Names
The Load Balancer and Proxies use Nginx `server_name` directives. Update the `domainname` parameters in the FiveM resource to match your actual domain/subdomains.

---

## 🛡 Security Note
This project was used in production in 2023. While innovative, it is provided "as-is" for portfolio and educational purposes. Ensure you audit the security of the Flask APIs (e.g., adding IP whitelisting for the API itself) before any modern production use.

## 📄 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🧠 Technical Prerequisites
Maintaining or extending DigitProtect requires a high-level understanding of the following technologies:
*   **Networking**: Deep knowledge of TCP/UDP protocols, reverse proxying, and traffic flow.
*   **Linux Security**: Proficiency with `iptables` (raw table, chains) and `ipset`.
*   **Python & Flask**: For modifying or securing the orchestration APIs.
*   **Go (Golang)**: For working with the low-level raw socket DPI engine.
*   **FiveM API**: Understanding of server-side scripting, `playerConnecting` events, and endpoint overrides.
