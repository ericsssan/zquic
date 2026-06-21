# Performance TODO

## High-bandwidth scaling (target: 100 Gbps)

### Ring buffer sizing
- [ ] Make `SEND_QUEUE_DEPTH` runtime-configurable (currently 256, overflows at ~3 Gbps/30ms)
- [ ] Make `MAX_SENT` runtime-configurable (currently 256, same limit — evictions break loss detection)
- [ ] Scale `SEND_BUF_SIZE` per-stream based on negotiated BDP (currently 64 KB, tight at 10 Mbps)

### Syscall reduction
- [x] GSO (`UDP_SEGMENT`) for Linux — batch N QUIC packets into 1 sendmsg (60× fewer send syscalls at 1 Gbps)
- [ ] recvmmsg for Linux — batch receive multiple datagrams per syscall
- [ ] Increase `SEND_BATCH` and `BATCH_SIZE` for higher packet rates (currently 32/16)

### Zero-copy send path
- [x] Encrypt directly into send queue slot (pkt_scratch → sq[].buf; enc_scratch removed)

### Pacing at high rates
- [ ] Sub-millisecond pacing for >1 Gbps (current 1ms timer tick limits pacing granularity)
- [ ] Consider io_uring or busy-poll for microsecond-level pacing
