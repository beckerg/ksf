## knsf - Kernel Network Service Framework for FreeBSD

*knsf* is a lightweight kernel network service framework for the purpose
of building simple network services that run in the FreeBSD kernel.
The motivation for this project was to build some generally useful RPC
handling software that is capable of both low-latency and high throughput,
yet does not sacrifice generality (i.e., it does not cut corners for the
purpose of achieving better benchmarks).

### Contents
The *knsf* repo includes two reference service implementations:
1. *kecho* is a loadable kernel module that implements an echo server which
simply echos back every byte of data that arrives on its receive queue
2. *krpc2* is a loadable kernel module that implements an RPC server which
responds only to **NFS NULL** procedure calls

Additionally, the repo includes two utilities to generate traffic to the above
services and measure the resulting latency and throughput (*echotest* and *rpctest*).

### Implementation
#### Abstractions
*knsf* provides two primary kernel abstractions: The connection (**struct conn**)
which manages a single socket, and the service (**struct svc**) which manages
a collection of connections.

#### Thread Pool
*knsf* provides a thread pool for the purpose of running short-lived asynchronous
tasks affined to a specific core.  All such tasks are executed in the context
of a kernel thread.

### Hardware
#### Client
* Intel(R) Xeon(R) CPU E5-2690 v3 @ 2.60GHz (x1)
* cc0: t6nex0 <Chelsio T62100-SO-CR> (direct wired)
* ix0: <Intel(R) PRO/10GbE PCI-Express> (direct wired)
* igb0: <Intel(R) PRO/1000
* [Supermicro SYS-6028R-TRT] https://www.supermicro.com/en/products/system/2U/6028/SYS-6028R-TRT.cfm
* X10DRi

#### Server
* Intel(R) Xeon(R) CPU E5-2690 v3 @ 2.60GHz
* cc0: t6nex0 <Chelsio T62100-SO-CR> (direct wired)
* ix0: <Intel(R) PRO/10GbE PCI-Express> (direct wired)
* [Supermicro SYS-6028R-TRT] https://www.supermicro.com/products/system/2U/6028/SYS-6028R-TRT.cfm
* X10DRi-T

### Results

The following results were obtained by running *rpctest* on the client,
which never issues more than one RPC per call to
[send(2)](https://www.freebsd.org/cgi/man.cgi?query=send&sektion=2),
and never receives more than one RPC per call to
[recv(2)](https://www.freebsd.org/cgi/man.cgi?query=recv&sektion=2)
(per thread).  The RPC server, however, is free to send and receive more
than one RPC request per call to both
[sosend(9)](https://www.freebsd.org/cgi/man.cgi?query=sosend&sektion=9),
and
[soreceive(9)](https://www.freebsd.org/cgi/man.cgi?query=soreceive&sektion=9).
Measurements taken by *rpctest* are end-to-end and include the full time
to encode each RPC call and decode/verify each RPC reply.

* Latency is meausred in microseconds, single-threaded (1T) with 1 inflight request.
For example: `sudo ./rpctest -j1 10.100.0.1`

* Throughput is measured in RPC/sec, multi-threaded (16T) with up to 224 inflight
requests.  For exaple: `sudo ./rpctest -j12 -a224 -c3000000 10.100.0.1`

INTF | Gbe  |  RXQ,TXQ  |  TOE  |   LATENCY 1T  |    RPC/s 1T   |     RPC/s 12T     |
:--- | ---: | :-------: | :---: | :-----------: | -------------:| -----------------:|
cc0  | 100  |    8,12   |  yes  |  10.3 - 10.7  | 92731 - 96143 | 6129372 - 6475970 |
cc1  | 100  |    8,12   |   no  |  12.9 - 13.1  | 75629 - 76941 | 4973351 - 5461142 |
ix0  |  10  |    -,-    |   no  |  32.7 - 32.9  | 21285 - 30509 | 5003414 - 5584970 |

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

#### /etc/sysctl.conf

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

#### /boot/loader.conf

```
cc_htcp_load="YES"
if_cxgbe_load="YES"
hw.cxgbe.nofldrxq="12"
hw.cxgbe.nofldtxq="12"
hw.cxgbe.fl_pktshift="2"
hw.cxgbe.autoneg=0
hw.ix.max_interrupt_rate="62500"
net.inet.tcp.soreceive_stream="1"
net.isr.bindthreads="1"
net.isr.maxthreads="-1"
net.isr.defaultqlimit="1024"
kern.ipc.nmbufs="16777216"
kern.ipc.nmbclusters="4194304"
machdep.hyperthreading_allowed="0"

```
