package main

/*
#include <sys/socket.h>
#include <linux/if.h>
*/
import "C"

import (
	"fmt"
	"log"
	"net"
	"os"
	"syscall"
	"unsafe"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pfring"
)

func clen(n []byte) int {
	for i := 0; i < len(n); i++ {
		if n[i] == 0 {
			return i
		}
	}
	return len(n)
}

func tunAlloc(name string, ip net.IP, mask net.IPMask) (int, string, error) {
	fd, err := syscall.Open("/dev/net/tun", syscall.O_RDWR, 0)
	if err != nil {
		return 0, "", fmt.Errorf("Couldn't open tun ctrl: %s", err)
	}
	var ifr C.struct_ifreq
	copy(ifr.ifr_ifrn[:], "gopacket0")
	*(*C.short)(unsafe.Pointer(&ifr.ifr_ifru)) = syscall.IFF_TAP | syscall.IFF_NO_PI
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(syscall.TUNSETIFF), uintptr(unsafe.Pointer(&ifr)))
	if errno != 0 {
		return 0, "", fmt.Errorf("Couldn't create tap interface: %s", errno)
	}

	actualName := string(ifr.ifr_ifrn[:clen(ifr.ifr_ifrn[:])])
	f, err := os.OpenFile(fmt.Sprintf("/proc/sys/net/ipv6/conf/%s/disable_ipv6", actualName), os.O_WRONLY, 0)
	if err != nil {
		return 0, "", fmt.Errorf("Couldn't access ipv6 setting: %s", err)
	}
	_, err = f.Write([]byte{'1'})
	if err != nil {
		return 0, "", fmt.Errorf("Couldn't disable ipv6 on interface: %s", err)
	}
	f.Close()

	sockfd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return 0, "", fmt.Errorf("Couldn't create control socket: %s", err)
	}
	defer syscall.Close(sockfd)

	var addr4 syscall.RawSockaddrInet4
	addr4.Family = syscall.AF_INET
	copy(addr4.Addr[:], ip.To4())
	*(*syscall.RawSockaddrInet4)(unsafe.Pointer(&ifr.ifr_ifru)) = addr4
	_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, uintptr(sockfd), uintptr(syscall.SIOCSIFADDR), uintptr(unsafe.Pointer(&ifr)))
	if errno != 0 {
		return 0, "", fmt.Errorf("Couldn't set ip: %s", errno)
	}
	copy(addr4.Addr[:], mask)
	*(*syscall.RawSockaddrInet4)(unsafe.Pointer(&ifr.ifr_ifru)) = addr4
	_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, uintptr(sockfd), uintptr(syscall.SIOCSIFNETMASK), uintptr(unsafe.Pointer(&ifr)))
	if errno != 0 {
		return 0, "", fmt.Errorf("Couldn't set mask: %s", errno)
	}

	_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, uintptr(sockfd), uintptr(syscall.SIOCGIFFLAGS), uintptr(unsafe.Pointer(&ifr)))
	if errno != 0 {
		return 0, "", fmt.Errorf("Couldn't get iflags: %s", errno)
	}
	*(*C.short)(unsafe.Pointer(&ifr.ifr_ifru)) |= syscall.IFF_UP
	_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, uintptr(sockfd), uintptr(syscall.SIOCSIFFLAGS), uintptr(unsafe.Pointer(&ifr)))
	if errno != 0 {
		return 0, "", fmt.Errorf("Couldn't set iflags: %s", errno)
	}

	return fd, actualName, nil
}

func main() {
	fd, name, err := tunAlloc("gopacket0", net.IPv4(192, 168, 140, 1), net.CIDRMask(24, 32))
	fmt.Printf("%#v %#v %#v\n", fd, name, err)
	if err != nil {
		return
	}
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := syscall.Read(fd, buf)
			if err != nil {
				log.Fatal("Error during read: ", err)
			}
			log.Println("[MONITOR] ", gopacket.NewPacket(buf[:n], layers.LayerTypeEthernet, gopacket.NoCopy).Dump())

			out := gopacket.NewSerializeBuffer()
			opt := gopacket.SerializeOptions{
				FixLengths:       true,
				ComputeChecksums: true,
			}

			eth := layers.Ethernet{
				SrcMAC:       net.HardwareAddr{6, 5, 4, 3, 2, 1},
				DstMAC:       net.HardwareAddr{1, 2, 3, 4, 5, 6},
				EthernetType: layers.EthernetTypeIPv4,
			}
			ip4 := layers.IPv4{
				Version:  4,
				SrcIP:    net.IPv4(192, 168, 0, 2),
				DstIP:    net.IPv4(192, 168, 0, 1),
				Protocol: layers.IPProtocolUDP,
				TTL:      100,
			}
			udp := layers.UDP{
				SrcPort: 1,
				DstPort: 1,
			}
			udp.SetNetworkLayerForChecksum(&ip4)

			err = gopacket.SerializeLayers(out, opt,
				&eth,
				&ip4,
				&udp,
				gopacket.Payload([]byte{'t', 'e', 's', 't'}))
			if err != nil {
				log.Fatal("Could not packet stuff together: ", err)
			}
			packetData := out.Bytes()
			log.Println("[MONITOR] sending: ", gopacket.NewPacket(packetData, layers.LayerTypeEthernet, gopacket.NoCopy).Dump())
			_, err = syscall.Write(fd, packetData)
			if err != nil {
				log.Fatal("Could not send packet")
			}
		}
	}()

	ring, err := pfring.NewRing("gopacket0", 65536, pfring.FlagPromisc)
	if err != nil {
		log.Fatal("could not ring around: ", err)
	}
	err = ring.SetDirection(pfring.ReceiveOnly)
	if err != nil {
		log.Fatal("dir not working: ", err)
	}
	err = ring.SetSocketMode(pfring.WriteAndRead)
	if err != nil {
		log.Fatal("mode not working: ", err)
	}
	err = ring.Enable()
	if err != nil {
		log.Fatal("enable not working: ", err)
	}

	buf := gopacket.NewSerializeBuffer()
	opt := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	eth := layers.Ethernet{
		SrcMAC:       net.HardwareAddr{6, 5, 4, 3, 2, 1},
		DstMAC:       net.HardwareAddr{1, 2, 3, 4, 5, 6},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip4 := layers.IPv4{
		Version:  4,
		SrcIP:    net.IPv4(192, 168, 0, 2),
		DstIP:    net.IPv4(192, 168, 0, 1),
		Protocol: layers.IPProtocolUDP,
		TTL:      100,
	}
	udp := layers.UDP{
		SrcPort: 1,
		DstPort: 1,
	}
	udp.SetNetworkLayerForChecksum(&ip4)

	err = gopacket.SerializeLayers(buf, opt,
		&eth,
		&ip4,
		&udp,
		gopacket.Payload([]byte{1, 2, 3, 4}))
	if err != nil {
		log.Fatal("Could not packet stuff together: ", err)
	}
	packetData := buf.Bytes()
	log.Println("[TEST] ", gopacket.NewPacket(packetData, layers.LayerTypeEthernet, gopacket.NoCopy).Dump())
	err = ring.WritePacketData(packetData)

	data, ci, err := ring.ZeroCopyReadPacketData()
	if err != nil {
		log.Fatal("error receiving packet: ", err)
	}
	log.Println("[TEST] answer: ", ci, "\n", gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy).Dump())
	log.Println("finished")
}
