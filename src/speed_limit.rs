// Token bucket speed limiter for per-user bandwidth control.
// Adapted from https://github.com/tikv/async-speed-limit (MIT / Apache-2.0)

use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{Instant, Sleep};

use crate::async_stream::{AsyncPing, AsyncStream};

const DEFAULT_REFILL_PERIOD: f64 = 0.1; // 100ms

#[derive(Debug)]
struct Bucket {
    last_updated: Instant,
    speed_limit: f64,
    refill: f64,
    value: f64,
    min_wait: f64,
}

impl Bucket {
    fn new(speed_limit: f64) -> Self {
        let refill = DEFAULT_REFILL_PERIOD;
        Self {
            last_updated: Instant::now(),
            speed_limit,
            refill,
            value: speed_limit * refill,
            min_wait: refill,
        }
    }

    fn capacity(&self) -> f64 {
        self.speed_limit * self.refill
    }

    fn update(&mut self, now: Instant) {
        let elapsed = (now - self.last_updated).as_secs_f64();
        self.last_updated = now;
        self.value = (self.value + elapsed * self.speed_limit).min(self.capacity());
    }

    fn consume(&mut self, size: f64) -> Duration {
        self.value -= size;
        if self.value >= 0.0 {
            Duration::ZERO
        } else {
            let wait_secs = (-self.value / self.speed_limit).max(self.min_wait);
            Duration::from_secs_f64(wait_secs)
        }
    }
}

/// A shared bandwidth limiter using a token bucket algorithm.
///
/// Multiple streams can share one `Limiter` to enforce a combined bandwidth cap.
/// Cloning a `Limiter` creates a new handle to the same underlying bucket.
#[derive(Clone, Debug)]
pub struct Limiter {
    state: Arc<Mutex<Bucket>>,
}

impl Limiter {
    /// Create a new limiter with the given speed limit in bytes per second.
    pub fn new(bytes_per_second: f64) -> Self {
        Self {
            state: Arc::new(Mutex::new(Bucket::new(bytes_per_second))),
        }
    }

    fn consume(&self, bytes: usize) -> Duration {
        let mut bucket = self.state.lock().unwrap();
        bucket.update(Instant::now());
        bucket.consume(bytes as f64)
    }
}

/// An `AsyncStream` wrapper that enforces bandwidth limits on both read and write.
///
/// Read and write directions each maintain independent delay state but share
/// the same underlying token bucket, limiting total throughput per user.
pub struct LimitedStream<S> {
    inner: S,
    limiter: Limiter,
    read_delay: Option<Pin<Box<Sleep>>>,
    write_delay: Option<Pin<Box<Sleep>>>,
}

impl<S> LimitedStream<S> {
    pub fn new(inner: S, limiter: Limiter) -> Self {
        Self {
            inner,
            limiter,
            read_delay: None,
            write_delay: None,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for LimitedStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();

        if let Some(delay) = &mut this.read_delay {
            match delay.as_mut().poll(cx) {
                Poll::Ready(()) => this.read_delay = None,
                Poll::Pending => return Poll::Pending,
            }
        }

        let filled_before = buf.filled().len();
        let result = Pin::new(&mut this.inner).poll_read(cx, buf);

        if let Poll::Ready(Ok(())) = &result {
            let n = buf.filled().len() - filled_before;
            if n > 0 {
                let wait = this.limiter.consume(n);
                if !wait.is_zero() {
                    this.read_delay = Some(Box::pin(tokio::time::sleep(wait)));
                }
            }
        }

        result
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for LimitedStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();

        if let Some(delay) = &mut this.write_delay {
            match delay.as_mut().poll(cx) {
                Poll::Ready(()) => this.write_delay = None,
                Poll::Pending => return Poll::Pending,
            }
        }

        let result = Pin::new(&mut this.inner).poll_write(cx, buf);

        if let Poll::Ready(Ok(n)) = &result
            && *n > 0
        {
            let wait = this.limiter.consume(*n);
            if !wait.is_zero() {
                this.write_delay = Some(Box::pin(tokio::time::sleep(wait)));
            }
        }

        result
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

impl<S: AsyncPing + Unpin> AsyncPing for LimitedStream<S> {
    fn supports_ping(&self) -> bool {
        self.inner.supports_ping()
    }

    fn poll_write_ping(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<bool>> {
        Pin::new(&mut self.get_mut().inner).poll_write_ping(cx)
    }
}

impl<S: AsyncStream> AsyncStream for LimitedStream<S> {}
