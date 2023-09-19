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

  `sudo ./rpctest -j1 -a1 172.16.100.200`
  
  | Gbe |  IFCE  | iperf3 |  netperf |  RPC/s  |  RTT  | FreeBSD |     Notes     |
  | --- | ------ | ------ | -------- | ------- | ----- | ------- | ------------- |
  | 100 |    cc0 |  28.2G | 77878.71 |   74170 |  11.5 |   12.3  | mtu 9000, toe |
  | 100 |    cc1 |  47.7G | 47814.40 |   64599 |  14.7 |   12.3  |               |
  |  10 |    ix1 |   9.4M |  9400.18 |   41213 |  19.7 |   12.3  |               |
  |     |        |        |          |         |       |         |               |
  | 100 |    cc0 |  29.4G | 74383.80 |   78255 |  11.3 |   13.1  | mtu 9000, toe |
  | 100 |    cc1 |  13.4G | 13388.69 |   68704 |  13.5 |   13.1  |               |
  |  10 |    ix1 |   9.4M |  9393.80 |   49937 |  18.5 |   13.1  |               |
  |     |        |        |          |         |       |         |               |
  | 100 |    cc0 |  29.2G | 91553.80 |   97257 |  10.2 |   15.x  | mtu 9000, toe |
  | 100 |    cc1 |  33.9G | 34463.69 |   73720 |  13.5 |   15.x  |               |
  |  40 | mlxen0 |  38.7G | 39223.91 |   63760 |  15.7 |   15.x  | mtu 9000      |
  |  40 | mlxen1 |  36.5G | 36342.42 |   63756 |  15.4 |   15.x  |               |
  |  10 |    ix0 |   9.9M |  9893.66 |   51251 |  19.5 |   15.x  | mtu 9000      |
  |  10 |    ix1 |   9.4M |  9403.33 |   52057 |  19.1 |   15.x  |               |

* Median RTT latency in microseconds, single-threaded with up to 128
requests in flight.

  `sudo ./rpctest -j1 -a128 -c9M 172.16.100.200`
  
  | Gbe |  IFCE  | iperf3 |  netperf |  RPC/s  |  RTT  | FreeBSD |     Notes     |
  | --- | ------ | ------ | -------- | ------- | ----- | ------- | ------------- |


Note that the *RTT* and *RPC/s* columns are the median of the all results
over 99 runs (each of which is the median of all jobs within the run).
This helps to mitigate the effects of non-deterministic flow affinity
and other anomalies.

Given that the 100Gbe and 10Gbe tests are not bandwidth limited by the NICs,
I suspect that both latency and throughput would improve given faster CPUs
with more cores, respectively.  To that end I would graciously accept donations
of newer more capable hardware to further this development and test effort.
Here is a short list of hardware I could put to immediate use:

* [Chelsio T62100-SO-CR](https://www.chelsio.com/nic/unified-wire-adapters/t62100-so-cr/)
* A 100Gbe switch

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
kern.ipc.maxsockbuf=16777216
hw.intr_storm_threshold=1048576
dev.t6nex.0.toe.ddp=1
dev.t6nex.0.toe.tx_zcopy=1
```

#### /etc/rc.conf.local
```
(kldstat |grep -q t4_tom) || kldload t4_tom
ifconfig_cc0="inet 172.16.100.202 netmask 255.255.255.0 mtu 9000 toe"
ifconfig_cc1="inet 172.16.101.202 netmask 255.255.255.0"
 
ifconfig_mlxen0="inet 172.16.40.202 netmask 255.255.255.0 mtu 9000"
ifconfig_mlxen1="inet 172.16.41.202 netmask 255.255.255.0"
 
ifconfig_ix0="inet 172.16.10.202 netmask 255.255.255.0 mtu 9000"
ifconfig_ix1="inet 172.16.11.202 netmask 255.255.255.0"
 
powerd_flags="-n hiadaptive -a hiadaptive -p333 -i35 -r50"
#powerd_flags="-n max -a max"
powerd_enable="YES"
 
sendmail_enable="NONE"
harvest_mask="351"
```

#### /boot/loader.conf.local

```
cpuctl_load="YES"
cpu_microcode_load="YES"
cpu_microcode_name="/boot/firmware/intel-ucode.bin"

cc_htcp_load="YES"
hwpmc_load="YES"
sem_load="YES"
ipmi_load="YES"
coretemp_load="YES"

t4fw_cfg_load="YES"
t5fw_cfg_load="YES"
t6fw_cfg_load="YES"
if_cxgbe_load="NO"
mlx4en_load="NO"

machdep.hyperthreading_allowed="0"

hw.ix.max_interrupt_rate="0"
hw.ix.rx_process_limit="-1"
hw.ix.enable_fdir="0"
hw.ix.unsupported_sfp="1"

hw.em.rx_process_limit="-1"
 
net.isr.defaultqlimit="2048"
net.isr.bindthreads="1"
net.isr.maxthreads="-1"
net.link.ifqmaxlen="2048"

net.inet.tcp.syncache.hashsize="1024"
net.inet.tcp.soreceive_stream="1"

vm.pmap.pti="0"
hw.ibrs_disable="1"
```

#### /sys/amd64/conf/SM1
```
include 	GENERIC
ident		SM1

options 	BREAK_TO_DEBUGGER
options 	KDB
options 	DDB

device 		ccr
device 		cxgbe
device 		lagg

device 		mlx4
device 		mlx4en
```
