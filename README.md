# Proxy Server based on eBPF
This forward any connection to Go server using eBPF sockmap

# Commands

## Terminal 1
```
go get github.com/cilium/ebpf/cmd/bpf2go@master
go generate && go build && sudo ./proxy_server
```

## Terminal 2
```
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

## Terminal 3
```
nc -v 192.168.1.6 777
```
# CC
[https://github.com/jsitnicki/ebpf-summit-2020](https://github.com/jsitnicki/ebpf-summit-2020)
[https://github.com/intel/istio-tcpip-bypass/blob/main/main.go](https://github.com/intel/istio-tcpip-bypass/blob/main/main.go)
# Docs
[https://man7.org/linux/man-pages/man7/bpf-helpers.7.html](https://man7.org/linux/man-pages/man7/bpf-helpers.7.html)
