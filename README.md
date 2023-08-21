## ksf - Kernel Sockets Framework for FreeBSD

*ksf* is a lightweight kernel network service framework for the purpose
of building simple network services that run in the FreeBSD kernel.
The motivation for this project was to build some generally useful RPC
handling software that is capable of both low-latency and high throughput,
yet does not sacrifice generality (i.e., it does not cut corners for the
purpose of achieving better benchmarks).

### Contents
The *ksf* repo includes two reference service implementations:
1. *kecho* is a loadable kernel module that implements an echo server which
simply echos back every byte of data that arrives on its receive queue
2. *krpc2* is a loadable kernel module that implements an RPC server which
responds only to **NFS NULL** procedure calls

Additionally, the repo includes two utilities to generate traffic to the above
services and measure the resulting latency and throughput (*echotest* and *rpctest*).

### Implementation
#### Abstractions
*ksf* provides two primary kernel abstractions: The connection (**struct conn**)
which manages a single socket, and the service (**struct svc**) which manages
a collection of connections.

#### Thread Pool
*ksf* provides a thread pool for the purpose of running short-lived asynchronous
tasks affined to a specific core.  All such tasks are executed in the context
of a kernel thread.

### Hardware
#### Client
* Intel(R) Xeon(R) CPU E5-2697a v4 @ 2.60GHz (16 cores)
* cc0: t6nex0 <Chelsio T62100-SO-CR> (direct wired)
* ix0: <Intel(R) PRO/10GbE PCI-Express> (direct wired)
* igb0: <Intel(R) PRO/1000
* [Supermicro SYS-6028R-T] https://www.supermicro.com/en/products/system/2U/6028/SYS-6028R-T.cfm
* X10DRi
* FreeBSD 12.1-STABLE r362887 SM1 
* FreeBSD 12.3-RELEASE SM1 

#### Server
* Intel(R) Xeon(R) CPU E5-2697a v4 @ 2.60GHz (16 cores)
* cc0: t6nex0 <Chelsio T62100-SO-CR> (direct wired)
* ix0: <Intel(R) PRO/10GbE PCI-Express> (direct wired)
* [Supermicro SYS-6028R-TRT] https://www.supermicro.com/products/system/2U/6028/SYS-6028R-TRT.cfm
* X10DRi-T
* FreeBSD 12.1-STABLE r362887 SM1 
* FreeBSD 12.3-RELEASE SM1 

### Results

The following results were obtained by running *rpctest* on the client,
which never issues more than one RPC (NFS NULL proc) per call to
[send(2)](https://www.freebsd.org/cgi/man.cgi?query=send&sektion=2),
and never retrieves more than one RPC per call to
[recv(2)](https://www.freebsd.org/cgi/man.cgi?query=recv&sektion=2)
(per thread).  The RPC server, however, is free to send and receive more
than one RPC request per call to both
[sosend(9)](https://www.freebsd.org/cgi/man.cgi?query=sosend&sektion=9),
and
[soreceive(9)](https://www.freebsd.org/cgi/man.cgi?query=soreceive&sektion=9).
Measurements taken by *rpctest* are end-to-end and include the full time
to encode each RPC call and decode/verify each RPC reply.

* Median RTT latency in microseconds, single-threaded with at most one
request in flight.

  For example: `sudo ./rpctest -j1 -a1 10.100.0.1`
  
  | Gbe |       Client     |       Server     |  RTT  |  RPC/s | Misc | FreeBSD |
  | --- | ---------------- | ---------------- | ----- | ------ | ---- | ------- |
  | 100 | cc0, E5-2690 v3  | cc0, E5-2690 v3  |  10.4 |  94833 |  toe | 12.1    |
  | 100 | cc1, E5-2690 v3  | cc1, E5-2690 v3  |  12.7 |  78152 |      | 12.1    |
  |  10 | ix0, E5-2690 v3  | ix0, E5-2690 v3  |  17.3 |  57397 |      | 12.1    |
  |     |                  |                  |       |        |      |         |
  | 100 | cc0, E5-2697A v4 | cc0, E5-2697A v4 |  11.0 |  73809 |  toe | 13.1    |
  | 100 | cc1, E5-2697A v4 | cc1, E5-2697A v4 |  13.0 |  64500 |      | 13.1    |
  |  10 | ix1, E5-2697A v4 | ix1, E5-2697A v4 |  18.2 |  45430 |      | 13.1    |

  For example: `sudo ./rpctest -j1 -a1 10.100.0.1`
  
  | Gbe | IFCE | iperf3 |  netperf |  RPC/s  |  RTT  | FreeBSD |     Notes     |
  | --- | ---- | ------ | -------- | ------- | ----- | ------- | ------------- |
  | 100 |  cc0 |  28.2G | 77878.71 |   74170 |  11.5 |   12.3  | mtu 9000, toe |
  | 100 |  cc1 |  47.7G | 47814.40 |   64599 |  14.7 |   12.3  |               |
  |  10 |  ix1 |   9.4M |  9400.18 |   41213 |  19.7 |   12.3  |               |
  |     |      |        |          |         |       |         |               |
  | 100 |  cc0 |  29.4G | 74383.80 |   78255 |  11.3 |   13.1  | mtu 9000, toe |
  | 100 |  cc1 |  13.4G | 13388.69 |   68704 |  13.5 |   13.1  |               |
  |  10 |  ix1 |   9.4M |  9393.80 |   49937 |  18.5 |   13.1  |               |
  |     |      |        |          |         |       |         |               |
  | 100 |  cc0 |  29.4G | 74383.80 |   74805 |  11.0 |   13.1  | mtu 9000, toe | patched
  | 100 |  cc1 |  13.4G | 13388.69 |   69544 |  13.6 |   13.1  |               |
  |  10 |  ix1 |   9.4M |  9393.80 |   49937 |  18.5 |   13.1  |               |

  For example: `sudo ./rpctest -j1 -a128 -c3M 10.100.0.1`
  
  | Gbe | IFCE | iperf3 |  netperf |  RPC/s  |  RTT  | FreeBSD |     Notes     |
  | --- | ---- | ------ | -------- | ------- | ----- | ------- | ------------- |
  | 100 |  cc0 |  28.2G | 77878.71 |  739787 | 171.6 |   12.3  | mtu 9000, toe |
  | 100 |  cc1 |  47.7G | 47814.40 |  851050 | 147.7 |   12.3  |               |
  |  10 |  ix1 |   9.4M |  9400.18 |  815816 | 149.7 |   12.3  |               |
  |     |      |        |          |         |       |         |               |
  | 100 |  cc0 |  29.4G | 74383.80 |  742753 | 169.6 |   13.1  | mtu 9000, toe |
  | 100 |  cc1 |  13.4G | 13388.69 |  843484 | 150.3 |   13.1  |               |
  |  10 |  ix1 |   9.4M |  9393.80 |  839950 | 151.1 |   13.1  |               |
  |     |      |        |          |         |       |         |               |
  | 100 |  cc0 |  29.4G | 74383.80 |  742753 | 169.6 |   13.1  | mtu 9000, toe | patched
  | 100 |  cc1 |  13.4G | 13388.69 |  843484 | 146.1 |   13.1  |               |
  |  10 |  ix1 |   9.4M |  9393.80 |  833722 | 148.1 |   13.1  |               |

  For example: `sudo ./rpctest -j8 -a128 -c3M 10.100.0.1`
  
  | Gbe | IFCE | iperf3 |  netperf |  RPC/s  |  RTT  | FreeBSD |     Notes     |
  | --- | ---- | ------ | -------- | ------- | ----- | ------- | ------------- |
  |     |      |        |          |         |       |         |               |
  | 100 |  cc0 |  29.4G | 74383.80 | 4539636 | 212.6 |   13.1  | mtu 9000, toe |
  | 100 |  cc1 |  13.4G | 13388.69 | 5905737 | 170.6 |   13.1  |               |
  |  10 |  ix1 |   9.4M |  9393.80 | 5786421 | 173.7 |   13.1  |               |
  |     |      |        |          |         |       |         |               |
  | 100 |  cc0 |  29.4G | 74383.80 | 4539636 | 212.6 |   13.1  | mtu 9000, toe | patched
  | 100 |  cc1 |  13.4G | 13388.69 | 5925737 | 167.8 |   13.1  |               |
  |  10 |  ix1 |   9.4M |  9393.80 | 5786421 | 173.7 |   13.1  |               |

  For example: `sudo ./rpctest -j16 -a128 -c3M 10.100.0.1`
  
  | Gbe | IFCE | iperf3 |  netperf |  RPC/s  |  RTT  | FreeBSD |     Notes     |
  | --- | ---- | ------ | -------- | ------- | ----- | ------- | ------------- |
  | 100 |  cc0 |  28.2G | 77878.71 |  178436 |  1237 |   12.3  | mtu 9000, toe |
  | 100 |  cc1 |  47.7G | 47814.40 | 6881704 |   284 |   12.3  |               |
  |  10 |  ix1 |   9.4M |  9400.18 | 6627787 |   269 |   12.3  |               |
  |     |      |        |          |         |       |         |               |
  | 100 |  cc0 |  29.4G | 74383.80 |  169680 | 16231 |   13.1  | mtu 9000, toe |
  | 100 |  cc1 |  13.4G | 13388.69 | 9725407 |   191 |   13.1  |               |
  |  10 |  ix1 |   9.4M |  9393.80 | 8194687 |   204 |   13.1  |               |

  For example: `sudo ./rpctest -j32 -a128 -c3M 10.100.0.1`
  
  | Gbe | IFCE | iperf3 |  netperf |  RPC/s  |  RTT  | FreeBSD |     Notes     |
  | --- | ---- | ------ | -------- | ------- | ----- | ------- | ------------- |
  | 100 |  cc0 |  28.2G | 77878.71 |    -    |    -  |   12.3  | mtu 9000, toe |
  | 100 |  cc1 |  47.7G | 47814.40 | 6586226 |   533 |   12.3  |               |
  |  10 |  ix1 |   9.4M |  9400.18 | 6677945 |   384 |   12.3  |               |
  |     |      |        |          |         |       |         |               |
  | 100 |  cc0 |  29.4G | 74383.80 |   -     |   -   |   13.1  | mtu 9000, toe |
  | 100 |  cc1 |  13.4G | 13388.69 |13244111 |   271 |   13.1  |               |
  |  10 |  ix1 |   9.4M |  9393.80 |11096407 |   261 |   13.1  |               |
  |     |      |        |          |         |       |         |               |
  | 100 |  cc0 |  29.4G | 74383.80 |   -     |   -   |   13.1  | mtu 9000, toe | patched
  | 100 |  cc1 |  13.4G | 13388.69 |13425250 |   264 |   13.1  |               |
  |  10 |  ix1 |   9.4M |  9393.80 |10299950 |   251 |   13.1  |               |


* Median RTT latency in microseconds, single-threaded with up to 128
requests in flight.

  For example: `sudo ./rpctest -j1 -a128 -c9M 10.100.0.1`
  
  | Gbe |       Client     |       Server     |  RTT  |  RPC/s  | Misc | FreeBSD |
  | --- | ---------------- | ---------------- | ----- | ------- | ---- | ------- |
  | 100 | cc0, E5-2690 v3  | cc0, E5-2690 v3  | 163.5 |  665310 |  toe | 12.1    |
  | 100 | cc1, E5-2690 v3  | cc1, E5-2690 v3  | 167.0 |  731182 |      | 12.1    |
  |  10 | ix0, E5-2690 v3  | ix0, E5-2690 v3  | 159.5 |  787885 |      | 12.1    |
  |     |                  |                  |       |         |      |         |
  | 100 | cc0, E5-2697A v4 | cc0, E5-2697A v4 | 139.1 |  918982 |  toe | 13.1    |
  | 100 | cc1, E5-2697A v4 | cc1, E5-2697A v4 | 119.8 | 1062374 |      | 13.1    |
  |  10 | ix1, E5-2697A v4 | ix1, E5-2697A v4 | 123.2 | 1037836 |      | 13.1    |

* Median RTT latency in microseconds, twelve threads with up to 224
requests in flight (per thread).

  For example: `sudo ./rpctest -j12 -a224 -c9M 10.100.0.1`
  
  | Gbe |       Client     |       Server     |  RTT  |   RPC/s  | Misc | FreeBSD |
  | --- | ---------------- | ---------------- | ----- | -------- | ---- | ------- |
  | 100 | cc0, E5-2690 v3  | cc0, E5-2690 v3  | 413.2 |  6259603 |  toe | 12.1    |
  | 100 | cc1, E5-2690 v3  | cc1, E5-2690 v3  | 383.7 |  5240423 |      | 12.1    |
  |  10 | ix0, E5-2690 v3  | ix0, E5-2690 v3  | 343.1 |  4761223 |      | 12.1    |
  |     |                  |                  |       |          |      |         |
  | 100 | cc0, E5-2697A v4 | cc0, E5-2697A v4 | 356.2 |  4311268 |  toe | 13.1    |
  | 100 | cc1, E5-2697A v4 | cc1, E5-2697A v4 | 263.6 |  9733830 |      | 13.1    |
  |  10 | ix1, E5-2697A v4 | ix1, E5-2697A v4 | 252.5 | 10471898 |      | 13.1    |

  And: `sudo ./rpctest -j32 -a128 -c9M 10.100.0.1`
  
  | Gbe |       Client     |       Server     |  RTT  |   RPC/s  | Misc | FreeBSD |
  | --- | ---------------- | ---------------- | ----- | -------- | ---- | ------- |
  | 100 | cc0, E5-2697A v4 | cc0, E5-2697A v4 | 356.2 |  4311268 |  toe | 13.1    |
  | 100 | cc1, E5-2697A v4 | cc1, E5-2697A v4 | 263.6 |  9733830 |      | 13.1    |
  |  10 | ix1, E5-2697A v4 | ix1, E5-2697A v4 | 252.5 | 10471898 |      | 13.1    |

Note that the *RTT* and *RPC/s* columns are the median of the all results
over 99 runs (each of which is the median of all jobs within the run).
This helps to mitigate the effects of non-deterministic flow affinity
and other anomalies.

Given that the 100Gbe and 10Gbe tests are not bandwidth limited by the NICs,
I suspect that both latency and throughput would improve given faster CPUs
with more cores, respectively.  To that end I would graciously accept donations
of newer more capable hardware to further this development and test effort.
Here is a short list of hardware I could put to immediate use:

* E5-2697A-v4 E5-2690-v4
* E5-2698A-v3
* [Chelsio T62100-SO-CR](https://www.chelsio.com/nic/unified-wire-adapters/t62100-so-cr/)
* A 100Gbe switch

The **Xeon 6142** and E5-2697A-v4 with their 16 cores would allow clean use
of 16 receive queues on the **T62100**.
Additional **T62100**'s would allow me to test **dual-CPU + dual-NIC**
configurations as well as Chelsio's switchless ring topology.

### TODO
1. Limit received request queuing
2. Leverage snd soupcall to avoid blocking in sosend()
3. Improve UDP connection handling
4. rpctest/echotest should accept hostnames as well as dot notation
5. Implement NFS getattr for a more useful real-world comparison
6. Implement NFS read/write to facilitate throughput measurements

### Bugs
Unloading the **krpc2** module while there are active connections requires
the following patch to avoid a kernel panic on svn versions lower than
-r349810:
* https://bugs.freebsd.org/bugzilla/show_bug.cgi?id=238789

### Configuration

#### /etc/sysctl.conf.local

```
net.inet.raw.maxdgram=16384
net.inet.raw.recvspace=16384
net.inet.ip.redirect=0
net.inet.ip.intr_queue_maxlen=1024
net.inet.tcp.path_mtu_discovery=0
net.inet.tcp.sendbuf_inc=32768
net.inet.tcp.recvbuf_inc=65536
net.inet.tcp.sendspace=32768
net.inet.tcp.path_mtu_discovery=0
net.inet.tcp.hostcache.expire=1
net.inet.tcp.sendbuf_max=16777216
net.inet.tcp.recvbuf_max=16777216
net.inet.tcp.cc.algorithm=htcp
net.local.stream.recvspace=65536
net.local.stream.sendspace=65536
net.route.netisr_maxqlen=2048
hw.intr_storm_threshold=20000
kern.ipc.maxsockbuf=16777216
kern.ipc.somaxconn=8192
dev.t6nex.0.toe.ddp=1
dev.t6nex.0.toe.tx_zcopy=1
```

#### /etc/rc.conf.local
```
powerd_enable="YES"
powerd_flags="-n hiadaptive -a hiadaptive -p333 -i35 -r65"
performance_cpu_freq="NONE"
performance_cx_lowest="LOW"
economy_cpu_freq="NONE"
economy_cx_lowest="LOW"
(kldstat |grep -q t4_tom) || kldload t4_tom
ifconfig_cc0="inet 10.100.0.1 netmask 255.255.255.0 -tso -lro -vlanhwtso toe"
ifconfig_cc1="inet 10.100.1.1 netmask 255.255.255.0 -tso -lro -vlanhwtso"
ifconfig_ix0="inet 10.10.0.1 netmask 255.255.255.0 -tso -lro -vlanhwtso"
ifconfig_ix1="inet 10.10.1.1 netmask 255.255.255.0 -tso -lro -vlanhwtso"
```

#### /boot/loader.conf.local

```
cc_htcp_load="YES"
if_cxgbe_load="YES"
hw.cxgbe.nofldrxq="-8"
hw.cxgbe.nofldtxq="-12"
hw.cxgbe.fl_pktshift="2"
hw.cxgbe.autoneg=0
hw.ix.max_interrupt_rate="0"
hw.ix.rx_process_limit="-1"
hw.em.rx_process_limit="-1"
hw.igb.rx_process_limit="-1"
net.inet.tcp.soreceive_stream="1"
net.isr.bindthreads="1"
net.isr.maxthreads="-1"
net.isr.defaultqlimit="1024"
kern.ipc.nmbufs="16777216"
kern.ipc.nmbclusters="4194304"
machdep.hyperthreading_allowed="0"
hint.apic.0.clock=0
hint.atrtc.0.clock=0
coretemp_load="YES"

```

#### /sys/amd64/conf/SM1
```
include 	GENERIC
ident		SM1

options 	CONSPEED=115200
options 	BREAK_TO_DEBUGGER
options 	DDB

#options 	SOCKBUF_DEBUG
#options 	INVARIANTS
#options 	INVARIANT_SUPPORT

device 		cxgbe
```
