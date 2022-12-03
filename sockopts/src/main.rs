use std::mem;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::unix::io::AsRawFd;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aya::{Bpf, include_bytes_aligned};
use aya::maps::HashMap;
use aya::programs::CgroupSockopt;
use aya_log::BpfLogger;
use clap::Parser;
use log::{info, warn};
use socket2::{Domain, Socket, Type};
use tokio::{io, select, signal};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "/sys/fs/cgroup")]
    cgroup_path: String,
}


#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct ConnectionTuple {
    pub daddr: u32,
    pub dport: u32,
    pub saddr: u32,
    pub sport: u32,
}

#[derive(Copy, Clone, Debug)]
pub struct ConnectionTuple2 {
    pub dest: SocketAddr,
    pub src: SocketAddr,
}

impl From<&ConnectionTuple> for ConnectionTuple2 {
    fn from(value: &ConnectionTuple) -> Self {
        unsafe {
            let d_addr: [u8; 4] = core::mem::transmute([value.daddr]);
            let s_addr: [u8; 4] = core::mem::transmute([value.saddr]);

            ConnectionTuple2 {
                dest: SocketAddr::from((IpAddr::V4(Ipv4Addr::from(d_addr)), value.dport as u16)),
                src: SocketAddr::from((IpAddr::V4(Ipv4Addr::from(s_addr)), value.sport as u16)),
            }
        }
    }
}

unsafe impl aya::Pod for ConnectionTuple {}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct Metadata {
    pub identity: [u8; 256]
}

unsafe impl aya::Pod for Metadata {}

fn get_id(s: &[u8]) -> [u8; 256] {
    let mut id: [u8; 256] = [0; 256];
    for (i, b) in s.iter().enumerate() {
        id[i] = *b;
    }
    id
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    env_logger::init();

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
        let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/sockopts"
    ))?;
    #[cfg(not(debug_assertions))]
        let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/sockopts"
    ))?;
    // if let Err(e) = BpfLogger::init(&mut bpf) {
    //     This can happen if you remove all log statements from your eBPF program.
        // warn!("failed to initialize eBPF logger: {}", e);
    // }

    let mut metadata: HashMap<_, ConnectionTuple, Metadata> = HashMap::try_from(bpf.map_mut("HOWARDJOHN_MAP")?)?;
    metadata.insert(ConnectionTuple {
        daddr: 1,
        dport: 2,
        saddr: 3,
        sport: 4,
    }, Metadata {
        identity: get_id(b"manual"),
    }, 0).unwrap();
    let program: &mut CgroupSockopt = bpf.program_mut("get_sockopts").unwrap().try_into()?;
    let cgroup = std::fs::File::open(opt.cgroup_path.clone())?;
    program.load()?;
    program.attach(cgroup)?;
    let program: &mut CgroupSockopt = bpf.program_mut("set_sockopts").unwrap().try_into()?;
    let cgroup = std::fs::File::open(opt.cgroup_path.clone())?;
    program.load()?;
    program.attach(cgroup)?;

    info!("Waiting for Ctrl-C...");

    let addr: SocketAddr = "127.0.0.1:1234".parse().unwrap();
    let (tx, rx) = oneshot::channel::<()>();
    let (srv_tx, srv_rx) = oneshot::channel::<()>();
    let client = tokio::spawn(async move {
        // return;
        srv_rx.await;
        let s = Socket::new(Domain::IPV4, Type::STREAM, None).unwrap();
        info!("creating socket...");
        s.connect(&addr.into()).unwrap();
        unsafe {
            let mut optval: [libc::c_uchar; 256] = get_id(b"from userspace").map(|b| b as libc::c_uchar);
            let mut sz = (mem::size_of_val(&optval)) as libc::socklen_t;
            let ret = libc::setsockopt(
                s.as_raw_fd(),
                #[allow(overflowing_literals)]
                    0xdeadbeef,
                12,
                &optval as *const _ as *const libc::c_void,
                mem::size_of_val(&optval) as libc::socklen_t,
            );
            warn!("setsock got val ret={ret} optval={optval:?}");
            if ret != 0 && ret != -1 {
                panic!("set sock opt: {:?}", io::Error::last_os_error());
            }
        }
        info!("set sock opt done");
        info!("connected.");
        rx.await
    });

    let m = Arc::new(Mutex::new(metadata));
    let mm = m.clone();
    let server: JoinHandle<()> = tokio::spawn(async move {
        let l = TcpListener::bind(addr).await.unwrap();
        drop(srv_tx);
        let (s, _) = l.accept().await.unwrap();
        info!("accepted client, trying sockopt");
        unsafe {
            let mut optval: [libc::c_uchar; 256] = [0; 256];
            let mut sz = (mem::size_of_val(&optval)) as libc::socklen_t;
            let ret = libc::getsockopt(
                s.as_raw_fd(),
                // libc::SOL_SOCKET,
                // libc::SO_REUSEPORT,
                #[allow(overflowing_literals)]
                    0xdeadbeef,
                12,
                &mut optval as *const _ as *mut libc::c_void,
                &mut sz,
            );
            if ret != 0 {
                // tokio::time::sleep(Duration::from_millis(10000000)).await;
                warn!("get sock opt: {:?}", io::Error::last_os_error());
            }
            warn!("got val ret={ret} optval={optval:?}");
            let s = str_from_null_terminated_utf8_safe(&optval[..sz as usize]);
            warn!("string val: {:?}", s);
            if s != "from userspace" {
                panic!("got {s}");
            }
        }

        info!("accepted client and got opt");
        drop(tx);
        tokio::time::sleep(Duration::from_secs(25)).await;
    });
    select! {
        _ = client => {
            info!("client done");
        },
        _ = server => {
            info!("server done");
        },
        _ = signal::ctrl_c() => {

        }
    }
    ;
    let m = m.lock().unwrap();
    m.iter().for_each(|f| {
        let f = f.unwrap();
        let a: ConnectionTuple2 = (&f.0).into();
        info!("map {a:?}",);
    });
    info!("Exiting...");

    Ok(())
}

fn str_from_null_terminated_utf8_safe(s: &[u8]) -> &str {
    if s.iter().any(|&x| x == 0) {
        unsafe { str_from_null_terminated_utf8(s) }
    } else {
        std::str::from_utf8(s).unwrap()
    }
}

// unsafe: s must contain a null byte
unsafe fn str_from_null_terminated_utf8(s: &[u8]) -> &str {
    std::ffi::CStr::from_ptr(s.as_ptr() as *const _).to_str().unwrap()
}

// unsafe: s must contain a null byte, and be valid utf-8
unsafe fn str_from_null_terminated_utf8_unchecked(s: &[u8]) -> &str {
    std::str::from_utf8_unchecked(std::ffi::CStr::from_ptr(s.as_ptr() as *const _).to_bytes())
}