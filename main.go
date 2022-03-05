//go:build linux
// +build linux
// go get github.com/cilium/ebpf/cmd/bpf2go@master
//go:generate bpf2go -cc clang-11 -cflags "-g -O2 -Wall -Wextra" bpf proxy_server.c -- -I./headers

package main

import (
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// sudo cat  /sys/kernel/debug/tracing/trace_pipe
func main() {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Panicln(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	err := loadBpfObjects(&objs, nil)
	if err != nil {
		log.Panicln(err)
	}
	defer objs.Close()

	// Attach program
	netns, err := os.Open("/proc/self/ns/net")
	if err != nil {
		log.Panicln(err)
	}
	defer netns.Close()

	lnk, err := link.AttachNetNs(int(netns.Fd()), objs.bpfPrograms.ProxyDispatch)
	defer lnk.Close()
	if err != nil {
		log.Panicln(err)
	}

	// Create server
	ln, err := net.Listen("tcp", "127.0.0.1:12295")
	if err != nil {
		log.Panicln(err)
	}

	go func() {
		<-stopper
		log.Println("Stoping..")
		os.Exit(0)
	}()

	// Put server fd into map
	lnTCP := ln.(*net.TCPListener)
	f, err := lnTCP.File()
	if err != nil {
		log.Panicln(err)
	}

	err = objs.bpfMaps.ServerSocket.Put(uint32(0), uint64(f.Fd()))
	if err != nil {
		log.Panicln(err)
	}

	// Put ports
	err = objs.bpfMaps.EchoPorts.Put(uint16(0x0309), uint8(0))
	if err != nil {
		log.Panicln(err)
	}

	log.Println("Listening..")
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		log.Println("New connection", conn.RemoteAddr())
		go handleEcho(conn)
	}

}

// Handle
func handleEcho(conn net.Conn) {
	buf := make([]byte, 1024)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			if err != io.EOF {
				log.Println(err)
			}
			return
		}
		log.Println(string(buf[:n]))
		conn.Write(buf[:n])
	}
}
