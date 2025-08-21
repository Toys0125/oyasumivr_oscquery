use crate::mdns::{IDiscovery, MeaModDiscovery, OSCQueryServiceProfile, OSCServiceType};
use crate::{ OSCQueryInitError};
use log::{debug, error};
use std::sync::LazyLock;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

// Channels for passing discovered VRChat addresses to the client module
// These are managed internally by mdns_sidecar
static VRC_OSC_ADDR_TX: LazyLock<Mutex<Option<Sender<(String, u16)>>>> =
    LazyLock::new(|| Mutex::new(None));
static VRC_OSC_ADDR_RX: LazyLock<Mutex<Option<Receiver<(String, u16)>>>> =
    LazyLock::new(|| Mutex::new(None));
static VRC_OSCQUERY_ADDR_TX: LazyLock<Mutex<Option<Sender<(String, u16)>>>> =
    LazyLock::new(|| Mutex::new(None));
static VRC_OSCQUERY_ADDR_RX: LazyLock<Mutex<Option<Receiver<(String, u16)>>>> =
    LazyLock::new(|| Mutex::new(None));

static MDNS_DISCOVERY_INSTANCE: LazyLock<Mutex<Option<Box<dyn IDiscovery>>>> =
    LazyLock::new(|| Mutex::new(None));
static MDNS_MONITOR_TASK: LazyLock<Mutex<Option<JoinHandle<()>>>> =
    LazyLock::new(|| Mutex::new(None));
static SERVER_ADVERTISEMENT_PROFILE: LazyLock<Mutex<Option<OSCQueryServiceProfile>>> =
    LazyLock::new(|| Mutex::new(None));

static CLIENT_ENABLED: LazyLock<Mutex<bool>> = LazyLock::new(|| Mutex::new(false));
static SERVER_ENABLED: LazyLock<Mutex<bool>> = LazyLock::new(|| Mutex::new(false));

pub async fn init_client_channels(
) -> Result<(Receiver<(String, u16)>, Receiver<(String, u16)>), OSCQueryInitError> {
    debug!("Initializing the MDNS sidecar client channels...");
    // Only initialize once
    {
        let mut discovery_guard = MDNS_DISCOVERY_INSTANCE.lock().await;
        if discovery_guard.is_some() {
            debug!("MDNS discovery instance already exists. Returning existing receivers.");
            let osc_rx = VRC_OSC_ADDR_RX
                .lock()
                .await
                .take()
                .ok_or(OSCQueryInitError::MDNSInitFailed)?;
            let oscquery_rx = VRC_OSCQUERY_ADDR_RX
                .lock()
                .await
                .take()
                .ok_or(OSCQueryInitError::MDNSInitFailed)?;
            return Ok((osc_rx, oscquery_rx));
        }

        // Channels for mDNS service events (internal to MeaModDiscovery)
        let (osc_service_added_tx, mut osc_service_added_rx) = channel(10);
        let (osc_query_service_added_tx, mut osc_query_service_added_rx) = channel(10);
        let (osc_service_removed_tx, mut osc_service_removed_rx) = channel(10);
        let (osc_query_service_removed_tx, mut osc_query_service_removed_rx) = channel(10);

        // Create the mDNS discovery instance
        let discovery = MeaModDiscovery::new(
            osc_service_added_tx,
            osc_query_service_added_tx,
            osc_service_removed_tx,
            osc_query_service_removed_tx,
        );
        *discovery_guard = Some(Box::new(discovery));

        // Create the channels for client.rs and store the Sender halves internally
        {
            let (vrc_osc_tx, vrc_osc_rx) = channel(100);
            let (vrc_oscquery_tx, vrc_oscquery_rx) = channel(100);

            *VRC_OSC_ADDR_TX.lock().await = Some(vrc_osc_tx);
            *VRC_OSC_ADDR_RX.lock().await = Some(vrc_osc_rx); // Store RX for future calls to get_vrc_discovery_channels
            *VRC_OSCQUERY_ADDR_TX.lock().await = Some(vrc_oscquery_tx);
            *VRC_OSCQUERY_ADDR_RX.lock().await = Some(vrc_oscquery_rx); // Store RX for future calls to get_vrc_discovery_channels
        }

        // Start a task to monitor mDNS events and pass relevant ones to client
        let monitor_task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    Some(profile) = osc_service_added_rx.recv() => {
                        if profile.name.starts_with("VRChat-Client-") {
                            debug!("VRChat OSC Service Found: {}:{}", profile.address, profile.port);
                            // Get the sender from the LazyLock to send the event
                            if let Some(tx) = VRC_OSC_ADDR_TX.lock().await.as_ref() {
                                if let Err(e) = tx.send((profile.address.to_string(), profile.port)).await {
                                    error!("Failed to send VRC_OSC_ADDR_DISCOVERY: {:?}", e);
                                }
                            }
                        }
                    }
                    Some(profile) = osc_query_service_added_rx.recv() => {
                        if profile.name.starts_with("VRChat-Client-") {
                            debug!("VRChat OSCQuery Service Found: {}:{}", profile.address, profile.port);
                            // Get the sender from the LazyLock to send the event
                            if let Some(tx) = VRC_OSCQUERY_ADDR_TX.lock().await.as_ref() {
                                if let Err(e) = tx.send((profile.address.to_string(), profile.port)).await {
                                    error!("Failed to send VRC_OSCQUERY_ADDR_DISCOVERY: {:?}", e);
                                }
                            }
                        }
                    }
                    Some(name) = osc_service_removed_rx.recv() => {
                        if name.starts_with("VRChat-Client-") {
                            debug!("VRChat OSC Service Removed: {}", name);
                            // In a real scenario, you might want to clear the address in `client.rs`
                            // For simplicity, we'll just log here. Clearing means `None` for client.
                            // However, mDNS clients often hold the last known address until a new one is found.
                        }
                    }
                    Some(name) = osc_query_service_removed_rx.recv() => {
                        if name.starts_with("VRChat-Client-") {
                            debug!("VRChat OSCQuery Service Removed: {}", name);
                            // Same as above for removal
                        }
                    }
                    else => {
                        debug!("mDNS monitor task exiting.");
                        break;
                    }
                }
            }
        });
        *MDNS_MONITOR_TASK.lock().await = Some(monitor_task);
        // Refresh services immediately after starting
        /* if let Some(discovery) = discovery_guard.as_ref() {
            discovery.refresh_services().await;
        } */
        // Return the Receiver halves
        let osc_rx = VRC_OSC_ADDR_RX
            .lock()
            .await
            .take()
            .ok_or(OSCQueryInitError::MDNSInitFailed)?;
        let oscquery_rx = VRC_OSCQUERY_ADDR_RX
            .lock()
            .await
            .take()
            .ok_or(OSCQueryInitError::MDNSInitFailed)?;
        Ok((osc_rx, oscquery_rx))
    }
}

pub async fn deinit() {
    {
        // Stop the monitor task
        if let Some(task) = MDNS_MONITOR_TASK.lock().await.take() {
            task.abort();
        }
        // Unregister any advertised services
        if let Some(discovery) = MDNS_DISCOVERY_INSTANCE.lock().await.as_ref() {
            if let Some(profile) = SERVER_ADVERTISEMENT_PROFILE.lock().await.take() {
                if let Err(e) = discovery.unadvertise(profile).await {
                    error!(
                        "Failed to unadvertise server service during deinit: {:?}",
                        e
                    );
                }
            }
        }
        // Clear the discovery instance
        *MDNS_DISCOVERY_INSTANCE.lock().await = None;
        // Clear the internal channels
        *VRC_OSC_ADDR_TX.lock().await = None;
        *VRC_OSC_ADDR_RX.lock().await = None;
        *VRC_OSCQUERY_ADDR_TX.lock().await = None;
        *VRC_OSCQUERY_ADDR_RX.lock().await = None;
    }
    debug!("mDNS sidecar deinitialized.");
}

pub async fn mark_server_started(
    osc_port: u16,
    oscquery_port: u16,
    service_name: String,
) -> Result<(), String> {
    // Ensure the underlying mDNS discovery instance is initialized.
    // This assumes `init_client_channels` (or a similar initial setup) has been called.
    {
        let discovery_guard = MDNS_DISCOVERY_INSTANCE.lock().await;
        if discovery_guard.is_none() {
            // If not initialized, ensure client channels are set up first,
            // as this will also initialize the MDNS_DISCOVERY_INSTANCE.
            // This is a common pattern where server and client might both rely on the same mDNS daemon.
            // However, for server functionality only, you might want a separate init_server_discovery.
            // For now, we'll try to get channels, which initializes if not present.
            // Note: This 'init_client_channels' is a bit misnamed if it's also responsible for core MDNS daemon init.
            drop(discovery_guard); // Release lock before calling async fn
            if let Err(e) = init_client_channels().await {
                return Err(format!(
                    "mDNS discovery instance not initialized and failed to init: {:?}",
                    e
                ));
            }
        }
    }

    // Store the server advertisement profile
    let osc_profile = OSCQueryServiceProfile::new(
        service_name.clone(),
        "127.0.0.1".parse().unwrap(), // Or actual local IP if needed
        osc_port,
        OSCServiceType::OSC,
    );
    let oscquery_profile = OSCQueryServiceProfile::new(
        service_name.clone(),
        "127.0.0.1".parse().unwrap(), // Or actual local IP if needed
        oscquery_port,
        OSCServiceType::OSCQuery,
    );

    {
        let mut server_enabled = SERVER_ENABLED.lock().await;
        *server_enabled = true;
    }

    if let Some(discovery) = MDNS_DISCOVERY_INSTANCE.lock().await.as_ref() {
        if let Err(e) = discovery.advertise(osc_profile.clone()).await {
            return Err(e);
        }
        if let Err(e) = discovery.advertise(oscquery_profile.clone()).await {
            // Try to unadvertise the first one if the second fails
            let _ = discovery.unadvertise(osc_profile).await;
            return Err(e);
        }
        *SERVER_ADVERTISEMENT_PROFILE.lock().await = Some(oscquery_profile); // Store one of them for unadvertising
    } else {
        return Err("mDNS discovery not initialized.".to_string());
    }
    debug!("MDNS server advertisements started.");
    Ok(())
}

pub async fn mark_server_stopped() -> Result<(), String> {
    {
        let mut server_enabled = SERVER_ENABLED.lock().await;
        *server_enabled = false;
    }

    if let Some(discovery) = MDNS_DISCOVERY_INSTANCE.lock().await.as_ref() {
        if let Some(profile) = SERVER_ADVERTISEMENT_PROFILE.lock().await.take() {
            // We need to unadvertise both OSC and OSCQuery profiles
            // Assuming the name and address are the same for both, we derive the OSC one.
            let osc_profile = OSCQueryServiceProfile::new(
                profile.name.clone(),
                profile.address.clone(),
                0, // Port doesn't matter for unregistering as it identifies by type and name
                OSCServiceType::OSC,
            );
            if let Err(e) = discovery.unadvertise(profile).await {
                error!("Failed to unadvertise OSCQuery service: {:?}", e);
            }
            if let Err(e) = discovery.unadvertise(osc_profile).await {
                error!("Failed to unadvertise OSC service: {:?}", e);
            }
        }
    }
    debug!("MDNS server advertisements stopped.");
    Ok(())
}

pub async fn mark_client_started() -> Result<(), String> {
    {
        let mut client_enabled = CLIENT_ENABLED.lock().await;
        *client_enabled = true;
    }
    // No direct action needed here, as the monitoring task already handles discovery
    // We just set the flag.
    debug!("MDNS client started.");
    Ok(())
}

pub async fn mark_client_stopped() -> Result<(), String> {
    {
        let mut client_enabled = CLIENT_ENABLED.lock().await;
        *client_enabled = false;
    }
    // No direct action needed, just set the flag.
    debug!("MDNS client stopped.");
    Ok(())
}
