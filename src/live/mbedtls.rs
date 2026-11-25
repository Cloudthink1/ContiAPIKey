use std::ffi::CString;
use std::ffi::c_char;
use std::ffi::c_int;
use std::ffi::c_void;
use std::future::poll_fn;
use std::io;
use std::pin::Pin;
use std::task::Context;
use std::task::Poll;
use std::task::ready;

use anyhow::Context as _;
use anyhow::Result;
use anyhow::ensure;
use libloading::Library;
use tokio::io::AsyncRead;
use tokio::io::AsyncWrite;
use tokio::io::ReadBuf;
#[cfg(test)]
use tokio::net::TcpStream;

const WANT_READ: c_int = -0x6900;
const WANT_WRITE: c_int = -0x6880;
const NET_SEND_FAILED: c_int = -0x004E;
const NET_RECV_FAILED: c_int = -0x004C;
const TLS_RECORD: usize = 16 * 1024;

type SendCallback = unsafe extern "C" fn(*mut c_void, *const u8, usize) -> c_int;
type RecvCallback = unsafe extern "C" fn(*mut c_void, *mut u8, usize) -> c_int;
type Create = unsafe extern "C" fn(
    *mut *mut c_void,
    *const c_char,
    *const u8,
    usize,
    *mut c_void,
    SendCallback,
    RecvCallback,
) -> c_int;
type Control = unsafe extern "C" fn(*mut c_void) -> c_int;
type Read = unsafe extern "C" fn(*mut c_void, *mut u8, usize) -> c_int;
type Write = unsafe extern "C" fn(*mut c_void, *const u8, usize) -> c_int;
type Free = unsafe extern "C" fn(*mut c_void);

pub struct MbedTls {
    socket: Box<BioHandle>,
    context: *mut c_void,
    handshake: Control,
    read: Read,
    write: Write,
    close: Control,
    free: Free,
    pending_write: Vec<u8>,
    _library: Library,
}

struct BioHandle(Box<dyn Bio>);

// The Mbed TLS context and its BIO socket have a single owner and are accessed through &mut self.
unsafe impl Send for MbedTls {}

impl MbedTls {
    #[cfg(test)]
    pub async fn connect(socket: TcpStream, host: &str, roots: &[u8]) -> Result<Self> {
        Self::connect_bio(socket, host, roots).await
    }

    pub(crate) async fn connect_bio(
        socket: impl Bio + 'static,
        host: &str,
        roots: &[u8],
    ) -> Result<Self> {
        let mut stream = Self::new(Box::new(socket), host, roots)?;
        let handshake = stream.handshake;
        let owner = &mut stream;
        poll_fn(move |cx| Self::drive(owner, cx, |state| unsafe { handshake(state) }))
            .await
            .context("Mbed TLS 1.3 handshake or certificate verification failed")?;
        Ok(stream)
    }

    fn new(socket: Box<dyn Bio>, host: &str, roots: &[u8]) -> Result<Self> {
        let executable = std::env::current_exe()?;
        let directory = executable
            .parent()
            .context("locate APDU executable directory")?;
        #[cfg(test)]
        let directory = if directory.file_name() == Some(std::ffi::OsStr::new("deps")) {
            directory
                .parent()
                .context("locate Cargo profile directory")?
        } else {
            directory
        };
        let path = directory.join("codex-apdu-mbedtls.dll");
        let native = unsafe {
            libloading::os::windows::Library::load_with_flags(
                path,
                windows_sys::Win32::System::LibraryLoader::LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR
                    | windows_sys::Win32::System::LibraryLoader::LOAD_LIBRARY_SEARCH_SYSTEM32,
            )
        }
        .context("load codex-apdu-mbedtls.dll; build the live TLS bridge first")?;
        let library: Library = native.into();
        let create: Create = unsafe { *library.get(b"apdu_tls_create")? };
        let handshake = unsafe { *library.get(b"apdu_tls_handshake")? };
        let read = unsafe { *library.get(b"apdu_tls_read")? };
        let write = unsafe { *library.get(b"apdu_tls_write")? };
        let close = unsafe { *library.get(b"apdu_tls_close")? };
        let free = unsafe { *library.get(b"apdu_tls_free")? };
        let hostname = CString::new(host)?;
        let mut socket = Box::new(BioHandle(socket));
        let mut context = std::ptr::null_mut();
        let result = unsafe {
            create(
                &mut context,
                hostname.as_ptr(),
                roots.as_ptr(),
                roots.len(),
                (&mut *socket as *mut BioHandle).cast(),
                send,
                recv,
            )
        };
        ensure!(
            result == 0 && !context.is_null(),
            "initialize Mbed TLS: {result}"
        );
        Ok(Self {
            socket,
            context,
            handshake,
            read,
            write,
            close,
            free,
            pending_write: Vec::new(),
            _library: library,
        })
    }

    fn drive(
        &self,
        cx: &mut Context<'_>,
        mut operation: impl FnMut(*mut c_void) -> c_int,
    ) -> Poll<io::Result<usize>> {
        loop {
            match operation(self.context) {
                WANT_READ => ready!(self.socket.0.poll_read_ready(cx))?,
                WANT_WRITE => ready!(self.socket.0.poll_write_ready(cx))?,
                result if result >= 0 => return Poll::Ready(Ok(result as usize)),
                result => {
                    return Poll::Ready(Err(io::Error::other(format!("Mbed TLS error {result}"))));
                }
            }
        }
    }
}

impl Drop for MbedTls {
    fn drop(&mut self) {
        unsafe { (self.free)(self.context) };
        zeroize::Zeroize::zeroize(&mut self.pending_write);
    }
}

impl AsyncRead for MbedTls {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let read = self.read;
        let bytes = buf.initialize_unfilled();
        let count = ready!(self.drive(cx, |state| unsafe {
            read(state, bytes.as_mut_ptr(), bytes.len())
        }))?;
        buf.advance(count);
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for MbedTls {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.pending_write.is_empty() {
            if buf.is_empty() {
                return Poll::Ready(Ok(0));
            }
            self.pending_write
                .extend_from_slice(&buf[..buf.len().min(TLS_RECORD)]);
        } else if !buf.starts_with(&self.pending_write) {
            return Poll::Ready(Err(io::Error::other(
                "TLS write buffer changed during a pending write",
            )));
        }
        let write = self.write;
        let result = ready!(self.drive(cx, |state| unsafe {
            write(state, self.pending_write.as_ptr(), self.pending_write.len())
        }));
        zeroize::Zeroize::zeroize(&mut self.pending_write);
        Poll::Ready(result)
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let close = self.close;
        ready!(self.drive(cx, |state| unsafe { close(state) }))?;
        Poll::Ready(Ok(()))
    }
}

/// Supplies nonblocking ciphertext I/O to the native TLS engine.
pub(crate) trait Bio: Send {
    fn try_write(&self, bytes: &[u8]) -> io::Result<usize>;
    fn try_read(&self, bytes: &mut [u8]) -> io::Result<usize>;
    fn poll_read_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>>;
    fn poll_write_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>>;
}

#[cfg(test)]
impl Bio for TcpStream {
    fn try_write(&self, bytes: &[u8]) -> io::Result<usize> {
        TcpStream::try_write(self, bytes)
    }

    fn try_read(&self, bytes: &mut [u8]) -> io::Result<usize> {
        TcpStream::try_read(self, bytes)
    }

    fn poll_read_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        TcpStream::poll_read_ready(self, cx)
    }

    fn poll_write_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        TcpStream::poll_write_ready(self, cx)
    }
}

unsafe extern "C" fn send(context: *mut c_void, buf: *const u8, len: usize) -> c_int {
    let socket = unsafe { &*context.cast::<BioHandle>() };
    let bytes = unsafe { std::slice::from_raw_parts(buf, len) };
    match socket.0.try_write(bytes) {
        Ok(count) => count as c_int,
        Err(err) if err.kind() == io::ErrorKind::WouldBlock => WANT_WRITE,
        Err(_) => NET_SEND_FAILED,
    }
}

unsafe extern "C" fn recv(context: *mut c_void, buf: *mut u8, len: usize) -> c_int {
    let socket = unsafe { &*context.cast::<BioHandle>() };
    let bytes = unsafe { std::slice::from_raw_parts_mut(buf, len) };
    match socket.0.try_read(bytes) {
        Ok(count) => count as c_int,
        Err(err) if err.kind() == io::ErrorKind::WouldBlock => WANT_READ,
        Err(_) => NET_RECV_FAILED,
    }
}

pub fn root_bundle(certs: impl IntoIterator<Item = impl AsRef<[u8]>>) -> Vec<u8> {
    let mut bundle = Vec::new();
    for cert in certs {
        let der = cert.as_ref();
        bundle.extend_from_slice(&(der.len() as u32).to_be_bytes());
        bundle.extend_from_slice(der);
    }
    bundle
}
