// simple_socks5_ipv4.go
package main

import (
	"encoding/binary"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"time"
)

var idleTimeout time.Duration

func init() {
	tStr := os.Getenv("IDLE_TIMEOUT")
	if tStr == "" {
		idleTimeout = 5 * time.Second
	} else {
		sec, err := strconv.Atoi(tStr)
		if err != nil || sec <= 0 {
			idleTimeout = 5 * time.Second
		} else {
			idleTimeout = time.Duration(sec) * time.Second
		}
	}
	log.Printf("[CONFIG] Idle timeout = %v", idleTimeout)
}

// SOCKS5 session handler
func handleConn(conn net.Conn) {
	defer conn.Close()
	client := conn.RemoteAddr().String()
	log.Printf("[SOCKS5] new from %s", client)

	// Handshake
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return
	}
	if buf[0] != 0x05 {
		return
	}
	n := int(buf[1])
	if _, err := io.ReadFull(conn, make([]byte, n)); err != nil {
		return
	}
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	// Request
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return
	}

	cmd := hdr[1]
	atyp := hdr[3]

	switch cmd {
	case 0x01: // CONNECT
		handleTCPConnect(conn, client, atyp)

	case 0x03: // UDP ASSOCIATE
		handleUDP(conn, client)

	default:
		_, _ = conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	}
}

// TCP CONNECT
func handleTCPConnect(conn net.Conn, client string, atyp byte) {
	var dest string

	switch atyp {
	case 0x01: // IPv4
		ipb := make([]byte, 4)
		if _, err := io.ReadFull(conn, ipb); err != nil {
			return
		}
		pb := make([]byte, 2)
		if _, err := io.ReadFull(conn, pb); err != nil {
			return
		}
		dest = net.IP(ipb).String() + ":" + strconv.Itoa(int(binary.BigEndian.Uint16(pb)))

	case 0x03: // DOMAIN
		var l [1]byte
		if _, err := io.ReadFull(conn, l[:]); err != nil {
			return
		}
		name := make([]byte, l[0])
		if _, err := io.ReadFull(conn, name); err != nil {
			return
		}
		pb := make([]byte, 2)
		if _, err := io.ReadFull(conn, pb); err != nil {
			return
		}
		dest = string(name) + ":" + strconv.Itoa(int(binary.BigEndian.Uint16(pb)))

	default:
		_, _ = conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	log.Printf("[SOCKS5] [%s] CONNECT → %s", client, dest)

	dialer := net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	target, err := dialer.Dial("tcp4", dest)
	if err != nil {
		time.Sleep(200 * time.Millisecond)
		target, err = dialer.Dial("tcp4", dest)
		if err != nil {
			_, _ = conn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			log.Printf("[SOCKS5] [%s] connect fail → %s (%v)", client, dest, err)
			return
		}
	}

	if tcp2, ok := target.(*net.TCPConn); ok {
		_ = tcp2.SetKeepAlive(true)
		_ = tcp2.SetKeepAlivePeriod(30 * time.Second)
	}
	defer target.Close()

	// Reply success
	if _, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	// log.Printf("[SOCKS5] [%s] TCP tunnel open %s", client, dest)

	done := make(chan struct{}, 2)

	go func() {
		buf := make([]byte, 32*1024)
		for {
			_ = conn.SetReadDeadline(time.Now().Add(idleTimeout))
			n, err := conn.Read(buf)
			if n > 0 {
				// log.Printf("[SOCKS5] activity from %s client→target", client)
				if _, werr := target.Write(buf[:n]); werr != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		done <- struct{}{}
	}()

	go func() {
		buf := make([]byte, 32*1024)
		for {
			_ = target.SetReadDeadline(time.Now().Add(idleTimeout))
			n, err := target.Read(buf)
			if n > 0 {
				// log.Printf("[SOCKS5] activity from %s target→client", client)
				if _, werr := conn.Write(buf[:n]); werr != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		done <- struct{}{}
	}()

	<-done
	// log.Printf("[SOCKS5] timeout, closing TCP session for %s (%s)", client, dest)
}

// UDP ASSOCIATE
func handleUDP(conn net.Conn, client string) {
	localIP := conn.LocalAddr().(*net.TCPAddr).IP.To4()
	if localIP == nil {
		localIP = net.IPv4(0, 0, 0, 0)
	}

	udpAddr := &net.UDPAddr{IP: localIP, Port: 0}
	udpConn, err := net.ListenUDP("udp4", udpAddr)
	if err != nil {
		log.Println("UDP listen err:", err)
		return
	}
	defer udpConn.Close()

	port := uint16(udpConn.LocalAddr().(*net.UDPAddr).Port)
	resp := []byte{0x05, 0x00, 0x00, 0x01, localIP[0], localIP[1], localIP[2], localIP[3], byte(port >> 8), byte(port)}
	if _, err := conn.Write(resp); err != nil {
		return
	}

	log.Printf("[SOCKS5] [%s] UDP relay open at %s:%d", client, localIP.String(), port)

	buf := make([]byte, 65535)
	for {
		_ = udpConn.SetReadDeadline(time.Now().Add(idleTimeout))
		n, src, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				log.Printf("[SOCKS5] timeout, closing UDP relay for %s", client)
			} else {
				log.Println("UDP read err:", err)
			}
			return
		}

		if n < 10 {
			continue
		}

		// log.Printf("[SOCKS5] activity from %s UDP packet", client)

		frag := buf[2]
		if frag != 0x00 {
			continue
		}

		atyp := buf[3]
		offset := 4
		var host string
		switch atyp {
		case 0x01: // IPv4
			host = net.IP(buf[offset : offset+4]).String()
			offset += 4
		case 0x03: // DOMAIN
			l := int(buf[offset])
			offset++
			host = string(buf[offset : offset+l])
			offset += l
		default:
			continue
		}
		port := int(binary.BigEndian.Uint16(buf[offset : offset+2]))
		offset += 2

		destAddr := net.JoinHostPort(host, strconv.Itoa(port))
		payload := buf[offset:n]
		replyHeader := append([]byte{}, buf[3:offset]...)

		go func(payload []byte, dest string, src *net.UDPAddr, replyHeader []byte) {
			remoteAddr, err := net.ResolveUDPAddr("udp4", dest)
			if err != nil {
				return
			}
			remote, err := net.DialUDP("udp4", nil, remoteAddr)
			if err != nil {
				return
			}
			defer remote.Close()

			if _, err := remote.Write(payload); err != nil {
				return
			}

			rb := make([]byte, 65535)
			_ = remote.SetReadDeadline(time.Now().Add(idleTimeout))
			rn, _, err := remote.ReadFromUDP(rb)
			if err == nil && rn > 0 {
				// log.Printf("[SOCKS5] activity from %s UDP reply", client)
				reply := append([]byte{0, 0, 0}, replyHeader...)
				reply = append(reply, rb[:rn]...)
				_, _ = udpConn.WriteToUDP(reply, src)
			}
		}(append([]byte{}, payload...), destAddr, src, replyHeader)
	}
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "1080"
	}
	addr := "0.0.0.0:" + port

	ln, err := net.Listen("tcp4", addr)
	if err != nil {
		log.Fatalf("listen %s err: %v", addr, err)
	}
	log.Printf("SOCKS5 IPv4-only proxy with UDP support on %s (idle timeout %v)", addr, idleTimeout)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept err: %v", err)
			continue
		}
		if tcp, ok := conn.(*net.TCPConn); ok {
			_ = tcp.SetKeepAlive(true)
			_ = tcp.SetKeepAlivePeriod(30 * time.Second)
		}
		go handleConn(conn)
	}
}
