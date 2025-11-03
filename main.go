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
    io.ReadFull(conn, make([]byte, n))
    conn.Write([]byte{0x05, 0x00})

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
        conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
    }
}

// TCP CONNECT
func handleTCPConnect(conn net.Conn, client string, atyp byte) {
    var dest string

    switch atyp {
    case 0x01: // IPv4
        ipb := make([]byte, 4)
        io.ReadFull(conn, ipb)
        pb := make([]byte, 2)
        io.ReadFull(conn, pb)
        dest = net.IP(ipb).String() + ":" + strconv.Itoa(int(binary.BigEndian.Uint16(pb)))

    case 0x03: // DOMAIN
        var l [1]byte
        io.ReadFull(conn, l[:])
        name := make([]byte, l[0])
        io.ReadFull(conn, name)
        pb := make([]byte, 2)
        io.ReadFull(conn, pb)
        dest = string(name) + ":" + strconv.Itoa(int(binary.BigEndian.Uint16(pb)))

    default:
        conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
        return
    }

    log.Printf("[SOCKS5] [%s] CONNECT → %s", client, dest)

    target, err := net.Dial("tcp4", dest)
    if err != nil {
        conn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
        return
    }
    if tcp2, ok := target.(*net.TCPConn); ok {
        tcp2.SetKeepAlive(true)
        tcp2.SetKeepAlivePeriod(30 * time.Second)
    }
    defer target.Close()

    // Reply success
    conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
 //   log.Printf("[SOCKS5] [%s] TCP tunnel open %s", client, dest)

    done := make(chan struct{}, 2)

    go func() {
        buf := make([]byte, 32*1024)
        for {
            conn.SetReadDeadline(time.Now().Add(idleTimeout))
            n, err := conn.Read(buf)
            if n > 0 {
        //        log.Printf("[SOCKS5] activity from %s client→target", client)
                target.Write(buf[:n])
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
            target.SetReadDeadline(time.Now().Add(idleTimeout))
            n, err := target.Read(buf)
            if n > 0 {
      //          log.Printf("[SOCKS5] activity from %s target→client", client)
                conn.Write(buf[:n])
            }
            if err != nil {
                break
            }
        }
        done <- struct{}{}
    }()

    <-done
    //log.Printf("[SOCKS5] timeout, closing TCP session for %s (%s)", client, dest)
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
    conn.Write(resp)

    log.Printf("[SOCKS5] [%s] UDP relay open at %s:%d", client, localIP.String(), port)

    buf := make([]byte, 65535)
    for {
        udpConn.SetReadDeadline(time.Now().Add(idleTimeout))
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

        //log.Printf("[SOCKS5] activity from %s UDP packet", client)

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

        go func(payload []byte, dest string, src *net.UDPAddr) {
            remoteAddr, err := net.ResolveUDPAddr("udp4", dest)
            if err != nil {
                return
            }
            remote, err := net.DialUDP("udp4", nil, remoteAddr)
            if err != nil {
                return
            }
            defer remote.Close()

            remote.Write(payload)

            rb := make([]byte, 65535)
            remote.SetReadDeadline(time.Now().Add(idleTimeout))
            rn, _, err := remote.ReadFromUDP(rb)
            if err == nil && rn > 0 {
                //log.Printf("[SOCKS5] activity from %s UDP reply", client)
                reply := append([]byte{0, 0, 0}, buf[3:offset]...)
                reply = append(reply, rb[:rn]...)
                udpConn.WriteToUDP(reply, src)
            }
        }(append([]byte{}, payload...), destAddr, src)
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
    log.Printf("SOCKS5 IPv4-only proxy with QUIC/UDP support on %s (idle timeout %v)", addr, idleTimeout)

    for {
        conn, err := ln.Accept()
        if err != nil {
            log.Printf("accept err: %v", err)
            continue
        }
        if tcp, ok := conn.(*net.TCPConn); ok {
            tcp.SetKeepAlive(true)
            tcp.SetKeepAlivePeriod(30 * time.Second)
        }
        go handleConn(conn)
    }
}
