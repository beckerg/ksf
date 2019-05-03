# ksf
Kernel Sockets Framework for FreeBSD

* /etc/sysctl.conf
  * net.inet.raw.maxdgram=16384
  * net.inet.raw.recvspace=16384
  * net.inet.ip.redirect=0
  * net.inet.ip.intr_queue_maxlen=1024
  * net.inet.tcp.path_mtu_discovery=0
  * net.local.stream.recvspace=65536
  * net.local.stream.sendspace=65536
  * net.route.netisr_maxqlen=2048
  * hw.intr_storm_threshold=20000
  * kern.ipc.somaxconn=8192


* /boot/loader.conf
  * hw.ix.max_interrupt_rate="62500"
  * net.inet.tcp.soreceive_stream="1"
  * net.isr.bindthreads="1"
  * net.isr.maxthreads="-1"
  * net.isr.defaultqlimit="1024"
