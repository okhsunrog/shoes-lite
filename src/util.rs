use tokio::io::AsyncWriteExt;

#[inline]
pub fn allocate_vec(len: usize) -> Vec<u8> {
    vec![0; len]
}

// a cancellable alternative to AsyncWriteExt::write_all
#[inline]
pub async fn write_all<T: AsyncWriteExt + Unpin>(
    stream: &mut T,
    buf: &[u8],
) -> std::io::Result<()> {
    let mut i = 0;
    let n = buf.len();
    while i < n {
        let n = stream.write(&buf[i..]).await?;
        if n == 0 {
            return Err(std::io::ErrorKind::WriteZero.into());
        }
        i += n;
    }
    Ok(())
}

/// Bound cleanup so a broken peer cannot retain a cancelled connection forever.
pub(crate) const SHUTDOWN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

pub(crate) async fn shutdown_stream<T: tokio::io::AsyncWriteExt + Unpin + ?Sized>(stream: &mut T) {
    let _ = tokio::time::timeout(SHUTDOWN_TIMEOUT, stream.shutdown()).await;
}
