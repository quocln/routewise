//! The helper's Windows named pipe, `\\.\pipe\routewise`. The pipe's access
//! list does not let users create further pipe instances (that would let any
//! user stand in for the helper), so the usual read/write open is refused: the
//! client asks for exactly read, write-data and write-attributes. Any user can
//! create a pipe of that name while the service is down, so after opening, the
//! server is checked before a byte is sent: it must be the process the service
//! control manager reports for the running RouteWise service. The retry rule for
//! a busy pipe and the trust decision are plain logic and are compiled on every
//! host under test.
#![cfg_attr(not(windows), allow(dead_code))]

use std::io;

/// Win32 `ERROR_PIPE_BUSY`: every instance of the pipe is serving a client.
const ERROR_PIPE_BUSY: i32 = 231;
/// How many times a busy pipe is waited for before giving up.
const BUSY_ATTEMPTS: u32 = 5;
/// How long each wait for a free instance lasts.
#[cfg(windows)]
const BUSY_WAIT_MS: u32 = 2000;

/// What the service control manager says about the RouteWise service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ServiceProcess {
    running: bool,
    pid: u32,
}

/// Whether the pipe's server may be talked to: only the process of the running
/// service. A standard user cannot read the token of the system process, but
/// can ask the service control manager for its id. A stopped or unknown service
/// trusts nobody, and process id 0 is never a server.
fn server_is_trusted(server_pid: u32, service: Option<ServiceProcess>) -> bool {
    matches!(service, Some(ServiceProcess { running: true, pid }) if pid != 0 && pid == server_pid)
}

/// Runs `open` and, while it reports a busy pipe, `wait` and tries again, up to
/// `attempts` opens. Any other error ends the loop at once: a missing pipe
/// (`NotFound`) means the helper is not running.
fn open_with_retry<T>(
    attempts: u32,
    mut open: impl FnMut() -> io::Result<T>,
    mut wait: impl FnMut(),
) -> io::Result<T> {
    let mut tries = 1;
    loop {
        match open() {
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) && tries < attempts => {
                tries += 1;
                wait();
            }
            other => return other,
        }
    }
}

#[cfg(windows)]
mod windows_pipe {
    use std::io;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, IntoRawHandle, OwnedHandle};
    use std::{mem, ptr};

    use async_trait::async_trait;
    use tokio::net::windows::named_pipe::NamedPipeClient;
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAG_OVERLAPPED, OPEN_EXISTING, SECURITY_ANONYMOUS, SECURITY_SQOS_PRESENT,
    };
    use windows_sys::Win32::System::Pipes::{GetNamedPipeServerProcessId, WaitNamedPipeW};
    use windows_sys::Win32::System::Services::{
        CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatusEx, SC_HANDLE, SC_MANAGER_CONNECT,
        SC_STATUS_PROCESS_INFO, SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_STATUS_PROCESS,
    };

    use super::{open_with_retry, server_is_trusted, ServiceProcess, BUSY_ATTEMPTS, BUSY_WAIT_MS};
    use crate::rpc::transport::{BoxStream, Transport};

    /// GENERIC_READ | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES: within what the
    /// pipe grants to authenticated users, and what the Go client opens with.
    const CLIENT_ACCESS: u32 = 0x8000_0000 | 0x2 | 0x100;

    /// The service the helper registers, whose process must own the pipe.
    const SERVICE_NAME: &str = "RouteWise";

    pub struct PipeTransport {
        /// The pipe's name as UTF-16 with its terminating nul.
        name: Vec<u16>,
        /// Whether the server's identity is checked after opening. Only tests
        /// serve a pipe from an ordinary process.
        verify_server: bool,
    }

    impl PipeTransport {
        pub fn new(name: &str) -> Self {
            Self { name: name.encode_utf16().chain(Some(0)).collect(), verify_server: true }
        }

        /// A transport that talks to a pipe whoever serves it.
        #[cfg(test)]
        pub fn unverified(name: &str) -> Self {
            Self { verify_server: false, ..Self::new(name) }
        }
    }

    /// A service control manager or service handle, closed on drop.
    struct ScHandle(SC_HANDLE);

    impl Drop for ScHandle {
        fn drop(&mut self) {
            // SAFETY: the handle came from OpenSCManagerW/OpenServiceW and is closed once.
            unsafe { CloseServiceHandle(self.0) };
        }
    }

    /// The service's state and process id from the service control manager.
    /// Needs no administrator rights.
    fn service_process() -> Option<ServiceProcess> {
        // SAFETY: null machine and database names mean the local active
        // database; `name` is nul-terminated and outlives the calls.
        unsafe {
            let scm = OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_CONNECT);
            if scm.is_null() {
                return None;
            }
            let scm = ScHandle(scm);
            let name: Vec<u16> = SERVICE_NAME.encode_utf16().chain(Some(0)).collect();
            let service = OpenServiceW(scm.0, name.as_ptr(), SERVICE_QUERY_STATUS);
            if service.is_null() {
                return None;
            }
            let service = ScHandle(service);
            let mut status: SERVICE_STATUS_PROCESS = mem::zeroed();
            let mut needed = 0u32;
            let size = mem::size_of::<SERVICE_STATUS_PROCESS>() as u32;
            if QueryServiceStatusEx(service.0, SC_STATUS_PROCESS_INFO, ptr::from_mut(&mut status).cast(), size, &mut needed)
                == 0
            {
                return None;
            }
            Some(ServiceProcess { running: status.dwCurrentState == SERVICE_RUNNING, pid: status.dwProcessId })
        }
    }

    /// Refuses a pipe whose server is not the RouteWise service.
    fn verify_server(pipe: &OwnedHandle) -> io::Result<()> {
        let mut pid = 0u32;
        // SAFETY: `pipe` is an open pipe handle and `pid` a live local.
        if unsafe { GetNamedPipeServerProcessId(pipe.as_raw_handle(), &mut pid) } == 0 {
            return Err(io::Error::last_os_error());
        }
        if server_is_trusted(pid, service_process()) {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "untrusted helper: the pipe is not served by the RouteWise service",
            ))
        }
    }

    fn open_once(name: &[u16]) -> io::Result<OwnedHandle> {
        // SAFETY: `name` is nul-terminated and outlives the call; the other
        // pointers are allowed to be null.
        let handle = unsafe {
            CreateFileW(
                name.as_ptr(),
                CLIENT_ACCESS,
                0,
                ptr::null(),
                OPEN_EXISTING,
                // Overlapped is what tokio needs; anonymous impersonation keeps
                // the server from acting as this user.
                FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_ANONYMOUS,
                ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: CreateFileW returned a handle nothing else owns.
        Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
    }

    /// Blocks up to `BUSY_WAIT_MS` for a free instance.
    fn wait_for_instance(name: &[u16]) {
        // SAFETY: `name` is nul-terminated. A failed or timed-out wait is
        // simply followed by another open, which reports the real error.
        unsafe { WaitNamedPipeW(name.as_ptr(), BUSY_WAIT_MS) };
    }

    #[async_trait]
    impl Transport for PipeTransport {
        async fn connect(&self) -> io::Result<BoxStream> {
            let name = self.name.clone();
            let verify = self.verify_server;
            // CreateFileW, the busy wait and the identity lookups block, so
            // they stay off the runtime. A refused pipe closes here, before
            // anything was written to it.
            let handle = tokio::task::spawn_blocking(move || {
                let pipe = open_with_retry(BUSY_ATTEMPTS, || open_once(&name), || wait_for_instance(&name))?;
                if verify {
                    verify_server(&pipe)?;
                }
                Ok::<_, io::Error>(pipe)
            })
            .await
            .map_err(io::Error::other)??;
            // SAFETY: the handle is a pipe opened overlapped; tokio takes
            // ownership of it, closing it if registration fails.
            let client = unsafe { NamedPipeClient::from_raw_handle(handle.into_raw_handle())? };
            Ok(Box::new(client))
        }
    }
}

#[cfg(windows)]
pub use windows_pipe::PipeTransport;

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;

    fn busy() -> io::Error {
        io::Error::from_raw_os_error(ERROR_PIPE_BUSY)
    }

    fn service(running: bool, pid: u32) -> Option<ServiceProcess> {
        Some(ServiceProcess { running, pid })
    }

    #[test]
    fn only_the_process_of_the_running_service_is_trusted() {
        assert!(server_is_trusted(4242, service(true, 4242)));
        assert!(!server_is_trusted(4242, service(true, 4243)));
        // A stopped service, an unreadable one and an unknown one trust nobody.
        assert!(!server_is_trusted(4242, service(false, 4242)));
        assert!(!server_is_trusted(4242, None));
    }

    #[test]
    fn process_id_zero_is_never_a_trusted_server() {
        assert!(!server_is_trusted(0, service(true, 0)));
    }

    #[test]
    fn a_busy_pipe_is_waited_for_and_opened_again() {
        let opens = Cell::new(0);
        let waits = Cell::new(0);
        let result = open_with_retry(
            5,
            || {
                opens.set(opens.get() + 1);
                if opens.get() < 3 {
                    Err(busy())
                } else {
                    Ok("pipe")
                }
            },
            || waits.set(waits.get() + 1),
        );
        assert_eq!(result.unwrap(), "pipe");
        assert_eq!((opens.get(), waits.get()), (3, 2));
    }

    #[test]
    fn a_pipe_that_stays_busy_gives_up_with_the_busy_error() {
        let opens = Cell::new(0);
        let err = open_with_retry::<()>(
            3,
            || {
                opens.set(opens.get() + 1);
                Err(busy())
            },
            || {},
        )
        .unwrap_err();
        assert_eq!(opens.get(), 3);
        assert_eq!(err.raw_os_error(), Some(ERROR_PIPE_BUSY));
    }

    #[test]
    fn any_other_error_is_returned_without_waiting() {
        // ERROR_FILE_NOT_FOUND: the helper is not running.
        let waits = Cell::new(0);
        let err = open_with_retry::<()>(5, || Err(io::Error::from_raw_os_error(2)), || waits.set(waits.get() + 1))
            .unwrap_err();
        assert_eq!(err.raw_os_error(), Some(2));
        assert_eq!(waits.get(), 0);
    }

    #[cfg(windows)]
    mod live {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::windows::named_pipe::ServerOptions;

        use super::super::PipeTransport;
        use crate::rpc::transport::Transport;

        fn pipe_name(tag: &str) -> String {
            format!(r"\\.\pipe\routewise-test-{tag}-{}", std::process::id())
        }

        #[tokio::test]
        async fn exchanges_bytes_with_a_pipe_server() {
            let name = pipe_name("echo");
            let mut server = ServerOptions::new().first_pipe_instance(true).create(&name).unwrap();
            let echo = tokio::spawn(async move {
                server.connect().await.unwrap();
                let mut buf = [0u8; 4];
                server.read_exact(&mut buf).await.unwrap();
                server.write_all(&buf).await.unwrap();
                server.flush().await.unwrap();
            });
            let mut stream = PipeTransport::unverified(&name).connect().await.unwrap();
            stream.write_all(b"ping").await.unwrap();
            let mut back = [0u8; 4];
            stream.read_exact(&mut back).await.unwrap();
            assert_eq!(&back, b"ping");
            echo.await.unwrap();
        }

        #[tokio::test]
        async fn a_pipe_served_by_an_ordinary_process_is_refused() {
            let name = pipe_name("squat");
            let _server = ServerOptions::new().first_pipe_instance(true).create(&name).unwrap();
            let err = PipeTransport::new(&name).connect().await.err().expect("an untrusted server");
            assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
        }

        #[tokio::test]
        async fn a_missing_pipe_is_not_found() {
            let err = PipeTransport::new(&pipe_name("absent")).connect().await.err().expect("no server");
            assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
        }
    }
}
