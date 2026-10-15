use super::*;
use std::{
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    sync::mpsc,
};

struct PacketReader {
    rx: mpsc::UnboundedReceiver<Vec<u8>>,
    polls: Arc<AtomicUsize>,
}
impl AsyncRead for PacketReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.polls.fetch_add(1, Ordering::Relaxed);
        match self.rx.poll_recv(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => Poll::Ready(Ok(())),
            Poll::Ready(Some(packet)) => {
                buf.put_slice(&packet);
                Poll::Ready(Ok(()))
            }
        }
    }
}
struct PacketWriter {
    tx: mpsc::UnboundedSender<Vec<u8>>,
    short: bool,
}
impl AsyncWrite for PacketWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.tx.send(buf.to_vec()).unwrap();
        Poll::Ready(Ok(if self.short { buf.len() - 1 } else { buf.len() }))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test(start_paused = true)]
async fn idle_stack_has_no_polling_tick_and_udp_wakes_it() {
    let stack = TcpStack::new();
    let (input, rx) = mpsc::unbounded_channel();
    let (tx, mut output) = mpsc::unbounded_channel();
    let (udp, responses) = mpsc::unbounded_channel();
    let polls = Arc::new(AtomicUsize::new(0));
    let observed = polls.clone();
    let task = tokio::spawn(async move {
        stack
            .run_io(
                PacketReader { rx, polls },
                PacketWriter { tx, short: false },
                1500,
                responses,
            )
            .await
    });
    tokio::task::yield_now().await;
    let before = observed.load(Ordering::Relaxed);
    tokio::time::advance(std::time::Duration::from_secs(3600)).await;
    tokio::task::yield_now().await;
    assert_eq!(
        observed.load(Ordering::Relaxed),
        before,
        "idle TUN must sleep until I/O"
    );
    udp.send(vec![1, 2, 3]).unwrap();
    assert_eq!(output.recv().await.unwrap(), [1, 2, 3]);
    drop(input);
    assert_eq!(
        task.await.unwrap().unwrap_err().kind(),
        io::ErrorKind::UnexpectedEof
    );
}

#[tokio::test]
async fn short_packet_write_is_not_retried_as_a_suffix() {
    let (tx, mut rx) = mpsc::unbounded_channel();
    let mut writer = PacketWriter { tx, short: true };
    assert_eq!(
        write_packet(&mut writer, b"packet")
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::WriteZero
    );
    assert_eq!(rx.recv().await.unwrap(), b"packet");
    assert!(rx.try_recv().is_err());
}

fn tcp_packet(sequence: u32, ack: Option<u32>, payload: &[u8]) -> Vec<u8> {
    let builder = etherparse::PacketBuilder::ipv4([192, 0, 2, 2], [198, 51, 100, 2], 64)
        .tcp(40000, 443, sequence, 65535);
    let builder = match ack {
        Some(ack) => builder.ack(ack),
        None => builder.syn(),
    };
    let mut packet = Vec::new();
    builder.write(&mut packet, payload).unwrap();
    packet
}

#[tokio::test]
async fn tcp_round_trip_and_fin_progress_without_polling_fallback() {
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        let mut stack = TcpStack::new();
        let mut connections = stack.take_new_conn_rx().unwrap();
        let (input, rx) = mpsc::unbounded_channel();
        let (tx, mut output) = mpsc::unbounded_channel();
        let (_udp, responses) = mpsc::unbounded_channel();
        let task = tokio::spawn(async move {
            stack
                .run_io(
                    PacketReader {
                        rx,
                        polls: Arc::new(AtomicUsize::new(0)),
                    },
                    PacketWriter { tx, short: false },
                    1500,
                    responses,
                )
                .await
        });
        input.send(tcp_packet(100, None, &[])).unwrap();
        let mut connection = connections.recv().await.unwrap().connection;
        let synack = output.recv().await.unwrap();
        let ip = smoltcp::wire::Ipv4Packet::new_checked(&synack[..]).unwrap();
        let tcp = smoltcp::wire::TcpPacket::new_checked(ip.payload()).unwrap();
        assert!(tcp.syn() && tcp.ack());
        let seq = tcp.seq_number().0 as u32 + 1;
        input.send(tcp_packet(101, Some(seq), b"request")).unwrap();
        let mut buf = [0; 7];
        connection.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"request");
        connection.write_all(b"response").await.unwrap();
        loop {
            let packet = output.recv().await.unwrap();
            let ip = smoltcp::wire::Ipv4Packet::new_checked(&packet[..]).unwrap();
            let tcp = smoltcp::wire::TcpPacket::new_checked(ip.payload()).unwrap();
            if !tcp.payload().is_empty() {
                assert_eq!(tcp.payload(), b"response");
                break;
            }
        }
        input.send(tcp_packet(108, Some(seq + 8), &[])).unwrap();
        let closing = tokio::spawn(async move { connection.shutdown().await });
        loop {
            let packet = output.recv().await.unwrap();
            let ip = smoltcp::wire::Ipv4Packet::new_checked(&packet[..]).unwrap();
            let tcp = smoltcp::wire::TcpPacket::new_checked(ip.payload()).unwrap();
            if tcp.fin() {
                break;
            }
        }
        closing.abort();
        task.abort();
        let _ = task.await;
    })
    .await
    .expect("TCP bridge must progress on data/close notifications");
}

#[tokio::test]
async fn stack_eof_wakes_pending_tcp_read() {
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        let mut stack = TcpStack::new();
        let mut connections = stack.take_new_conn_rx().unwrap();
        let (input, rx) = mpsc::unbounded_channel();
        let (tx, _output) = mpsc::unbounded_channel();
        let (_udp, responses) = mpsc::unbounded_channel();
        let task = tokio::spawn(async move {
            stack
                .run_io(
                    PacketReader {
                        rx,
                        polls: Arc::new(AtomicUsize::new(0)),
                    },
                    PacketWriter { tx, short: false },
                    1500,
                    responses,
                )
                .await
        });
        input.send(tcp_packet(100, None, &[])).unwrap();
        let mut connection = connections.recv().await.unwrap().connection;
        drop(input);
        assert_eq!(
            task.await.unwrap().unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
        assert_eq!(connection.read(&mut [0; 1]).await.unwrap(), 0);
    })
    .await
    .expect("device failure must release pending TCP readers");
}
