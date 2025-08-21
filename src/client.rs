use log::{debug, error};
use std::sync::LazyLock;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

use crate::{
    mdns_sidecar,
    Error, OSCQueryInitError,
};

static INITIALIZED: LazyLock<Mutex<bool>> = LazyLock::new(|| Mutex::new(false));
static VRC_OSC_HOST: LazyLock<Mutex<Option<String>>> = LazyLock::new(|| Mutex::default());
static VRC_OSC_PORT: LazyLock<Mutex<Option<u16>>> = LazyLock::new(|| Mutex::default());
static VRC_OSCQUERY_HOST: LazyLock<Mutex<Option<String>>> = LazyLock::new(|| Mutex::default());
static VRC_OSCQUERY_PORT: LazyLock<Mutex<Option<u16>>> = LazyLock::new(|| Mutex::default());

static DISCOVERY_MONITOR_TASK: LazyLock<Mutex<Option<JoinHandle<()>>>> =
    LazyLock::new(|| Mutex::new(None));

pub async fn get_vrchat_osc_host() -> Option<String> {
    let osc_host = VRC_OSC_HOST.lock().await;
    osc_host.clone()
}

pub async fn get_vrchat_osc_port() -> Option<u16> {
    let osc_port = VRC_OSC_PORT.lock().await;
    osc_port.clone()
}

pub async fn get_vrchat_osc_address() -> Option<(String, u16)> {
    let osc_host = VRC_OSC_HOST.lock().await;
    let osc_port = VRC_OSC_PORT.lock().await;
    if osc_host.is_none() || osc_port.is_none() {
        return None;
    }
    let osc_host = osc_host.clone().unwrap();
    let osc_port = osc_port.clone().unwrap();
    Some((osc_host, osc_port))
}

pub async fn get_vrchat_oscquery_host() -> Option<String> {
    let oscquery_host = VRC_OSCQUERY_HOST.lock().await;
    oscquery_host.clone()
}

pub async fn get_vrchat_oscquery_port() -> Option<u16> {
    let oscquery_port = VRC_OSCQUERY_PORT.lock().await;
    oscquery_port.clone()
}

pub async fn get_vrchat_oscquery_address() -> Option<(String, u16)> {
    let oscquery_host = VRC_OSCQUERY_HOST.lock().await;
    let oscquery_port = VRC_OSCQUERY_PORT.lock().await;
    if oscquery_host.is_none() || oscquery_port.is_none() {
        return None;
    }
    let oscquery_host = oscquery_host.clone().unwrap();
    let oscquery_port = oscquery_port.clone().unwrap();
    Some((oscquery_host, oscquery_port))
}

pub async fn init() -> Result<(), Error> {
    // Stop if we've already initialized
    {
        let mut initialized = INITIALIZED.lock().await;
        if *initialized {
            debug!("MDNS client already initialized. Skipping.");
            return Ok(());
        }
        *initialized = true;
    }

    // Initialize the MDNS sidecar and get the receiver channels from it
    let (mut osc_rx, mut oscquery_rx) = match mdns_sidecar::init_client_channels().await {
        Ok(channels) => channels,
        Err(e) => {
            error!("Could not initialize MDNS sidecar channels: {:#?}", e);
            *INITIALIZED.lock().await = false;
            return Err(Error::InitError(e));
        }
    };

    // Spawn a task to listen for discovery events
    let monitor_task = tokio::spawn(async move {
        loop {
            tokio::select! {
                Some((host, port)) = osc_rx.recv() => {
                    debug!("Received VRC_OSC_ADDR_DISCOVERY: {}:{}", host, port);
                    *VRC_OSC_HOST.lock().await = Some(host);
                    *VRC_OSC_PORT.lock().await = Some(port);
                }
                Some((host, port)) = oscquery_rx.recv() => {
                    debug!("Received VRC_OSCQUERY_ADDR_DISCOVERY: {}:{}", host, port);
                    *VRC_OSCQUERY_HOST.lock().await = Some(host);
                    *VRC_OSCQUERY_PORT.lock().await = Some(port);
                }
                else => {
                    debug!("Discovery monitor task exiting.");
                    break;
                }
            }
        }
    });
    *DISCOVERY_MONITOR_TASK.lock().await = Some(monitor_task);

    if let Err(e) = mdns_sidecar::mark_client_started().await {
        error!("Could not mark the MDNS Client as started: {:#?}", e);
        *INITIALIZED.lock().await = false;
        return Err(Error::InitError(crate::OSCQueryInitError::MDNSInitFailed));
    }

    Ok(())
}

pub async fn deinit() -> Result<(), Error> {
    // Ensure to only deinitialize if already initialized
    {
        let initialized = INITIALIZED.lock().await;
        if !*initialized {
            return Err(Error::InitError(OSCQueryInitError::NotYetInitialized));
        }
    }
    // Stop the MDNS sidecar (client part)
    if let Err(e) = crate::mdns_sidecar::mark_client_stopped().await {
        error!("Could not stop the MDNS Client: {:#?}", e);
        return Err(Error::InitError(crate::OSCQueryInitError::MDNSInitFailed));
    }
    // Stop the discovery monitor task
    if let Some(task) = DISCOVERY_MONITOR_TASK.lock().await.take() {
        task.abort();
    }
    // Deinitialize the MDNS sidecar module
    crate::mdns_sidecar::deinit().await;
    // Reset state
    {
        *VRC_OSC_HOST.lock().await = None;
        *VRC_OSC_PORT.lock().await = None;
        *VRC_OSCQUERY_HOST.lock().await = None;
        *VRC_OSCQUERY_PORT.lock().await = None;
        *INITIALIZED.lock().await = false;
    }
    Ok(())
}
