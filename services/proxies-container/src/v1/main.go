package main

import (
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"syscall"
	"time"
  "flag"
  "os"
  "reflect"
)

const (
	ETH_P_IP   = 0x0800 // IPv4 protocol ID
	SIZE_IP    = 20     // IPv4 header size
	SIZE_TCP   = 20     // TCP header size
	SIZE_UDP   = 8      // UDP header size
	SIZE_ETH   = 14     // Ethernet header size
	BUF_SIZE   = 65535  // Maximum size of the buffer for receiving packets
	PORT_STOCK = 2    // Port Source to stock
)

func main() {

  // Add command line arguments
	portArg := flag.Int("port", 30120, "Target port to monitor")
	ifaceArg := flag.String("iface", "ens3", "Network interface to use")
	ipArg := flag.String("ip", "127.0.0.1", "IP to listen")
	dstArg := flag.String("dst", "127.0.0.1", "Destination IP to listen")
	// Check if no arguments are provided
	if len(os.Args) == 1 {
		fmt.Println("Usage:")
		flag.PrintDefaults()
		os.Exit(1)
	}
  	// Parse command line arguments
	flag.Parse()

	// Open a raw socket for capturing packets
	sock, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(ETH_P_IP)))
	if err != nil {
		fmt.Println("Failed to open socket:", err)
		return
	}
	defer syscall.Close(sock)

	pid := os.Getpid()

	fmt.Println("PID:", pid)


	// Bind the socket to a network interface and a specific port
	iface := *ifaceArg
	targetPort := *portArg
	targetIp := *ipArg
	dstIp := *dstArg
	addr := &syscall.SockaddrLinklayer{
		Protocol: htons(ETH_P_IP),
		Ifindex:  getInterfaceIndex(iface),
	}
	err = syscall.Bind(sock, addr)
	if err != nil {
		fmt.Println("Failed to bind socket:", err)
		return
	}

	// Create a buffer for receiving packets
	buf := make([]byte, BUF_SIZE)

	// Create a map to store the source ports for each IP address
	ports := make(map[string][]uint16)
	// Create a map to store the IP address
	ingame := make(map[string][]uint16)
	// Create a map to store the last activity time for each IP address
	lastActive := make(map[string]time.Time)

	go func() {
		for {
			time.Sleep(1 * time.Second)
			now := time.Now()
			for ip, _ := range ingame {
				if now.Sub(lastActive[ip]) > 5*time.Second {
					// Unwhitelist the source ports
					exec.Command("ipset", "del", "insrc", ip + "," + dstIp).Run()
					for _, p := range ingame[ip] {
						exec.Command("ipset", "del", "sourceports", ip + ",udp:" + strconv.Itoa(int(p)) + "," + dstIp).Run()
						fmt.Printf("\033[31mSource Port: %d Unwhitelisted for %s ( inactive ) \033[0;37m\n", p, ip)
					}
					// Remove the IP from the 'ingame' map
					delete(ingame, ip)
					// Remove the IP from the 'lastActive' map
					delete(lastActive, ip)
					// REMOVE THE IP FROM THE 'ports' MAP
					delete(ports, ip)
					// Kill the current process
					os.Exit(0)

				}
			}
		}
	}()

	// Start capturing packets
	for {
		// Receive a packet
		n, _, err := syscall.Recvfrom(sock, buf, 0)
		if err != nil {
			fmt.Println("Failed to receive packet:", err)
			continue
		}


		// Parse the packet
		if n < SIZE_IP {
			continue
		}
		packetDstIp := net.IP(buf[SIZE_ETH+16:SIZE_ETH+20]).String()
		if packetDstIp != dstIp {
			continue
		}

		ip := net.IP(buf[SIZE_ETH+12 : SIZE_ETH+16]) // Correct this line
		if ip.To4() == nil {
			continue
		}
		proto := buf[SIZE_ETH+9]
		if proto != syscall.IPPROTO_TCP && proto != syscall.IPPROTO_UDP {
			continue
		}
		var srcPort uint16
		if proto == syscall.IPPROTO_TCP && n >= SIZE_IP+SIZE_TCP {
			//srcPort = uint16(buf[SIZE_ETH+SIZE_IP])<<8 | uint16(buf[SIZE_ETH+SIZE_IP+1])
			continue
		} else if proto == syscall.IPPROTO_UDP && n >= SIZE_IP+SIZE_UDP {
			srcPort = uint16(buf[SIZE_ETH+SIZE_IP])<<8 | uint16(buf[SIZE_ETH+SIZE_IP+1])
		}

		// Check if the packet's destination port matches the target port
		dstPort := uint16(buf[SIZE_ETH+SIZE_IP+2])<<8 | uint16(buf[SIZE_ETH+SIZE_IP+3])
		if dstPort != uint16(targetPort) {
			continue
		}

		// Check if ip.String() is equal to the IP address provided in the command line arguments drop the packet
		if ip.String() != targetIp {
			fmt.Printf("IP not equal to target IP")
			continue
		}


		// Store the source port for the IP address
		ipStr := ip.String()
		if len(ports[ipStr]) < PORT_STOCK {
			// Check if the port is already present in the list
			portExists := false
			for _, p := range ports[ipStr] {
				if p == srcPort {
					portExists = true
					break
				}
			}
			// Add the port to the list if it doesn't already exist
			if !portExists {
				ports[ipStr] = append(ports[ipStr], srcPort)
			}
		}

		// Update the last active time for the IP address
		lastActive[ipStr] = time.Now()

		// Print the source IP and source ports if the length of the ports list is equal to PORT_STOCK
		if len(ports[ipStr]) <= PORT_STOCK {
			// If the IP is not in the 'ingame' map
			if len(ingame[ipStr]) < PORT_STOCK {
				fmt.Printf("\033[33mSource IP: %s, Source Ports: %v, Destination Port: %d, Length: %d \033[0;37m\n", ipStr, ports[ipStr], dstPort, len(ingame[ipStr]))
				// Display the ports one by one
				if len(ingame[ipStr]) == 0 {
					exec.Command("ipset", "add", "insrc", ipStr + "," + dstIp).Run()
				}
				for _, p := range ports[ipStr] {
					// Add the port to the 'ingame' map
					containsValue := false
					for _, v := range ingame[ipStr] {
						if v == p {
							containsValue = true
							break
						}
					}
					if !containsValue {
						ingame[ipStr] = append(ingame[ipStr], p)
						exec.Command("ipset", "add", "sourceports", ipStr + ",udp:" + strconv.Itoa(int(p)) + "," + dstIp).Run()
						fmt.Printf("\033[32mSource Port: %d Whitelisted for %s \033[0;37m\n", p, ipStr)
					}

				}

				// Clear the 'ports' map for the IP
				ports[ipStr] = nil
				// REMOVE THE IP FROM THE 'ports' MAP
				delete(ports, ipStr)
			} else if len(ports[ipStr]) > len(ingame[ipStr]) {
				// check if the ports are the same
				if reflect.DeepEqual(ingame[ipStr], ports[ipStr]) {
					// If the ports are the same, do nothing
					continue
				} else {
					fmt.Printf("\033[0;31m/!\\ SPOOFED /!\\ Source IP: %s, Source Ports: %v \033[0;37m\n", ipStr, ports[ipStr])
					delete(ports, ipStr)
				}
			}
		}
	}
}

func htons(n uint16) uint16 {
	return (n<<8&0xff00 | n>>8&0xff)
}

func getInterfaceIndex(iface string) int {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		fmt.Println("Failed to get interface index:", err)
		return 0
	}
	return ifi.Index
}