## knsf - Kernel Network Service Framework for FreeBSD

*knsf* is a lightweight kernel network service framework for the purpose
of building network services that run in the FreeBSD kernel.
The motivation behind this project was to build generally useful software
that is able to achieve low-latency and high throughput of an RPC request
between a client application a kernel service over various types of networks
(as opposed to highly-specific software that sacrifices usability and
extensiblity for optimal results).

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
*knsf* provides two primary abstractions: The connection (**struct conn**) which
manages a single socket, and the service (**struct svc**) which manages
a collection of connections.

#### Thread Pool
*knfs* provides a thread pool for the purpose of running short-lived asynchronous
tasks affined to a specified core.  All such tasks are executed in the context
of a kernel thread.

### Hardware
#### Client
* Intel(R) Xeon(R) CPU E5-2680 v2 @ 2.80GHz
* cc0: t6nex0 <Chelsio T62100-SO-CR> (direct wired)
* ix0: <Intel(R) PRO/10GbE PCI-Express> (direct wired)
* igb0: <Intel(R) PRO/1000
* [Tyan S7055](https://tyan.com/Motherboards_S7055_S7055AGM3NR)

#### Server
* Intel(R) Xeon(R) CPU E5-2690 v3 @ 2.60GHz
* cc0: t6nex0 <Chelsio T62100-SO-CR> (direct wired)
* ix0: <Intel(R) PRO/10GbE PCI-Express> (direct wired)
* [Supermicro SYS-6028R-TRT](https://www.supermicro.com/products/system/2U/6028/SYS-6028R-TRT.cfm)

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
Measurements taken by *rpctest* include the full time to encode each RPC call
and decode/verify each RPC reply.

* Latency is meausred in microseconds, single-threaded (1T) with 1 inflight request.
For example: `sudo ./rpctest -j1 10.100.0.1`

* Throughput is measured in RPC/sec, multi-threaded (16T) with up to 224 inflight requests.
For example: `sudo ./rpctest -j16 -a224 -c3000000 10.100.0.1`

INTF | Gbe  |  RXQ,TXQ  |  TOE  | LATENCY | RPC/s 1T | RPC/s 16T |
:--- | ---: | :-------: | :---: | :-----: | --------:| ---------:|
cc0  | 100  |    8,12   |  yes  |   11.2  |   (1)    |   7382738 |
cc1  | 100  |    8,12   |   no  |   14.6  |   (1)    |   4143866 |
ix0  |  10  |   12,12   |   -   |   32.8  |  630546  |   4319407 |
igb0 |   1  |     8,8   |   -   |  125    |  566546  |   2924584 |

(1) Results alternate from roughly 400000 to 60000 RPC/s between successive
tests, need to investigate.

Given that the 100Gbe and 10Gbe tests are not bandwidth limited by the NICs,
I suspect that both latency and throughput would improve given faster CPUs
with more cores, respectively.  To that end I would graciously accept donations
of newer more capable hardware to further this development and test effort.
Here's a small list of hardware I could put to immediate use:

* [Xeon Gold 6142](https://ark.intel.com/content/www/us/en/ark/products/120487/intel-xeon-gold-6142-processor-22m-cache-2-60-ghz.html)
* [Chelsio T62100-SO-CR](https://www.chelsio.com/nic/unified-wire-adapters/t62100-so-cr/)
* A 100Gbe switch
* E5-2697A-v4
* E5-2690-v4
* E5-2687w-v2
* E5-2667-v2

The **Xeon 6142** and E5-2697A-v4 with their 16 cores would allow use of 16 receive
queues on the **T62100**.
Additional **T62100**'s would allow me to test **dual-CPU + dual-NIC**
configurations as well as Chelsio's switchless ring topology.

### TODO
1. Limit received request queuing
2. Leverage snd soupcall to avoid blocking in sosend()
3. Improve UDP connection handling
4. rpctest/echotest should accept hostnames as well as dot notation

### Bugs
Unloading the **krpc2** module while their are active connections requires
the following patch to avoid a kernel panic:
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
hw.ix.max_interrupt_rate="62500"
net.inet.tcp.soreceive_stream="1"
net.isr.bindthreads="1"
net.isr.maxthreads="-1"
net.isr.defaultqlimit="1024"
kern.ipc.nmbufs="16777216"
kern.ipc.nmbclusters="4194304"
t4fw_cfg_load="YES"
t5fw_cfg_load="YES"
t6fw_cfg_load="YES"
if_cxgbe_load="YES"
hw.cxgbe.nofldrxq="12"
hw.cxgbe.nofldtxq="12"
hw.cxgbe.fl_pktshift="2"
machdep.hyperthreading_allowed="0"
```
