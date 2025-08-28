use async_trait::async_trait;
use log::{debug, error};
use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::mpsc::{ Sender};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum OSCServiceType {
    Unknown,
    OSCQuery,
    OSC,
}

impl OSCServiceType {
    pub const SERVICE_OSCJSON_TCP: &str = "_oscjson._tcp.local.";
    pub const SERVICE_OSC_UDP: &str = "_osc._udp.local.";

    pub fn get_service_type_string(&self) -> &str {
        match self {
            OSCServiceType::OSC => OSCServiceType::SERVICE_OSC_UDP,
            OSCServiceType::OSCQuery => OSCServiceType::SERVICE_OSCJSON_TCP,
            OSCServiceType::Unknown => "UNKNOWN",
        }
    }

    pub fn from_service_string(s: &str) -> Self {
        match s {
            OSCServiceType::SERVICE_OSC_UDP => OSCServiceType::OSC,
            OSCServiceType::SERVICE_OSCJSON_TCP => OSCServiceType::OSCQuery,
            _ => OSCServiceType::Unknown,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OSCQueryServiceProfile {
    pub port: u16,
    pub name: String,
    pub address: IpAddr,
    pub service_type: OSCServiceType,
}

impl OSCQueryServiceProfile {
    pub fn new(name: String, address: IpAddr, port: u16, service_type: OSCServiceType) -> Self {
        Self {
            name,
            address,
            port,
            service_type,
        }
    }

    pub fn to_service_info(&self) -> ServiceInfo {
        let service_type_str = self.service_type.get_service_type_string();
        let host_name = format!("{}.osc.local.", self.name);
        let properties = [("txtvers", "1")];
        ServiceInfo::new(
            service_type_str,
            &self.name,
            &host_name,
            &self.address,
            self.port,
            &properties[..],
        )
        .unwrap() // We expect this to succeed with valid inputs
    }
}

#[async_trait]
pub trait IDiscovery: Send + Sync {
    async fn refresh_services(&self);
    async fn advertise(&self, profile: OSCQueryServiceProfile) -> Result<(), String>;
    async fn unadvertise(&self, profile: OSCQueryServiceProfile) -> Result<(), String>;

    async fn get_osc_query_services(&self) -> HashSet<OSCQueryServiceProfile>;
    async fn get_osc_services(&self) -> HashSet<OSCQueryServiceProfile>;
}

pub struct MeaModDiscovery {
    daemon: ServiceDaemon,
    registered_services: Mutex<HashMap<OSCQueryServiceProfile, ServiceInfo>>,
    osc_query_services: Arc<Mutex<HashSet<OSCQueryServiceProfile>>>,
    osc_services: Arc<Mutex<HashSet<OSCQueryServiceProfile>>>,
    // Removed service_event_tx as it was internal to this struct's event handling
    _event_handler_task: JoinHandle<()>,
}

impl MeaModDiscovery {
    pub fn new(
        osc_service_added_tx: Sender<OSCQueryServiceProfile>,
        osc_query_service_added_tx: Sender<OSCQueryServiceProfile>,
        osc_service_removed_tx: Sender<String>,
        osc_query_service_removed_tx: Sender<String>,
    ) -> Self {
        let daemon = ServiceDaemon::new().expect("Failed to create mDNS daemon");

        // IMPORTANT: Obtain the ServiceEvent receiver directly from the daemon
        // This receiver will get all events (found, resolved, removed)
        let osc_receiver = daemon
            .browse(OSCServiceType::SERVICE_OSC_UDP) // Start browsing for OSC services
            .expect("Failed to browse OSC services");
        let osc_query_receiver = daemon
            .browse(OSCServiceType::SERVICE_OSCJSON_TCP) // Start browsing for OSCQuery services
            .expect("Failed to browse OSCQuery services");

        let osc_query_services = Arc::new(Mutex::new(HashSet::new()));
        let osc_services = Arc::new(Mutex::new(HashSet::new()));

        let handler_osc_query_services = osc_query_services.clone();
        let handler_osc_services = osc_services.clone();

        let _event_handler_task = tokio::spawn(async move {
            MeaModDiscovery::handle_service_events(
                osc_receiver, // Pass the daemon's actual event receiver
                osc_query_receiver,
                handler_osc_query_services,
                handler_osc_services,
                osc_service_added_tx,
                osc_query_service_added_tx,
                osc_service_removed_tx,
                osc_query_service_removed_tx,
            )
            .await;
        });

        MeaModDiscovery {
            daemon,
            registered_services: Mutex::new(HashMap::new()),
            osc_query_services,
            osc_services,
            _event_handler_task,
        }
    }

    async fn handle_service_events(
        osc_receiver: mdns_sd::Receiver<ServiceEvent>, // This is now the daemon's event receiver
        osc_query_receiver: mdns_sd::Receiver<ServiceEvent>,
        osc_query_services: Arc<Mutex<HashSet<OSCQueryServiceProfile>>>,
        osc_services: Arc<Mutex<HashSet<OSCQueryServiceProfile>>>,
        osc_service_added_tx: Sender<OSCQueryServiceProfile>,
        osc_query_service_added_tx: Sender<OSCQueryServiceProfile>,
        osc_service_removed_tx: Sender<String>,
        osc_query_service_removed_tx: Sender<String>,
    ) {
        loop {
            tokio::select! {
                event_result = osc_receiver.recv_async() => {
                    match event_result {
                        Ok(event) => {
                            Self::process_service_event(
                                event,
                                &osc_query_services,
                                &osc_services,
                                &osc_service_added_tx,
                                &osc_query_service_added_tx,
                                &osc_service_removed_tx,
                                &osc_query_service_removed_tx,
                            ).await;
                        },
                        Err(e) => {
                            error!("mDNS service event receiver error: {:?}. Handler exiting.", e);
                            break; // Channel closed, so exit the loop
                        }
                    }
                }
                event_result = osc_query_receiver.recv_async() => {
                    match event_result {
                        Ok(event) => {
                            Self::process_service_event(
                                event,
                                &osc_query_services,
                                &osc_services,
                                &osc_service_added_tx,
                                &osc_query_service_added_tx,
                                &osc_service_removed_tx,
                                &osc_query_service_removed_tx,
                            ).await;
                        },
                        Err(e) => {
                            error!("mDNS service event receiver error: {:?}. Handler exiting.", e);
                            break; // Channel closed, so exit the loop
                        }
                    }
                }
                else => {
                    debug!("mDNS service event handler exiting.");
                    break;
                }
            }
        }
    }

    async fn process_service_event(
        event: ServiceEvent,
        osc_query_services: &Arc<Mutex<HashSet<OSCQueryServiceProfile>>>,
        osc_services: &Arc<Mutex<HashSet<OSCQueryServiceProfile>>>,
        osc_service_added_tx: &Sender<OSCQueryServiceProfile>,
        osc_query_service_added_tx: &Sender<OSCQueryServiceProfile>,
        osc_service_removed_tx: &Sender<String>,
        osc_query_service_removed_tx: &Sender<String>,
    ) {
        match event {
            ServiceEvent::ServiceFound(service_type, instance_name) => {
                debug!(
                    "Service found: type={}, instance={}",
                    service_type, instance_name
                );
                // When a service is found, we should let the daemon resolve it.
                // The resolution happens automatically if you've subscribed to the service type with `browse`.
                // The resolved info will then come as a ServiceResolved event.
            }
            ServiceEvent::ServiceResolved(info) => {
                debug!("Service resolved: {:?}", info);
                let service_type = OSCServiceType::from_service_string(info.get_type());

                // IMPORTANT: Ensure addresses are handled safely.
                // get_addresses() returns a slice, which might be empty.
                let address = if let Some(addr) = info.get_addresses().iter().next() {
                    addr.clone()
                } else {
                    error!("Resolved service {} has no IP addresses.", info.get_fullname());
                    return; // Skip if no address
                };

                let profile = OSCQueryServiceProfile {
                    name: info.get_fullname().to_string(),
                    address,
                    port: info.get_port(),
                    service_type: service_type.clone(),
                };

                match service_type {
                    OSCServiceType::OSC => {
                        let mut services = osc_services.lock().await;
                        if services.insert(profile.clone()) {
                            if let Err(e) = osc_service_added_tx.send(profile).await {
                                error!("Failed to send OSC service added event: {:?}", e);
                            }
                        }
                    }
                    OSCServiceType::OSCQuery => {
                        let mut services = osc_query_services.lock().await;
                        if services.insert(profile.clone()) {
                            if let Err(e) = osc_query_service_added_tx.send(profile).await {
                                error!("Failed to send OSCQuery service added event: {:?}", e);
                            }
                        }
                    }
                    _ => {}
                }
            }
            ServiceEvent::ServiceRemoved(service_type, instance_name) => {
                debug!(
                    "Service removed: type={}, instance={}",
                    service_type, instance_name
                );
                let service_type_enum = OSCServiceType::from_service_string(&service_type);

                match service_type_enum {
                    OSCServiceType::OSC => {
                        let mut services = osc_services.lock().await;
                        // Find and remove the service by name (since we don't have full profile)
                        // Note: For robust removal, you might need to store more than just the name if names aren't unique enough.
                        services.retain(|p| p.name != instance_name);
                        if let Err(e) = osc_service_removed_tx.send(instance_name).await {
                            error!("Failed to send OSC service removed event: {:?}", e);
                        }
                    }
                    OSCServiceType::OSCQuery => {
                        let mut services = osc_query_services.lock().await;
                        // Find and remove the service by name
                        services.retain(|p| p.name != instance_name);
                        if let Err(e) = osc_query_service_removed_tx.send(instance_name).await {
                            error!("Failed to send OSCQuery service removed event: {:?}", e);
                        }
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }
}

#[async_trait]
impl IDiscovery for MeaModDiscovery {
    async fn refresh_services(&self) {
        debug!("Refreshing mDNS services. (Browse calls made in new()).");
        self.daemon
            .browse(OSCServiceType::SERVICE_OSC_UDP)
            .expect("Failed to browse OSC services");
        self.daemon
            .browse(OSCServiceType::SERVICE_OSCJSON_TCP)
            .expect("Failed to browse OSCQuery services");
    }

    async fn advertise(&self, profile: OSCQueryServiceProfile) -> Result<(), String> {
        let service_info = profile.to_service_info();
        match self.daemon.register(service_info.clone()) {
            Ok(_) => {
                debug!(
                    "Advertising Service {} of type {} on {}:{}",
                    profile.name,
                    profile.service_type.get_service_type_string(),
                    profile.address,
                    profile.port
                );
                match profile.service_type {
                    OSCServiceType::OSC => {
                        self.osc_services.lock().await.insert(profile.clone());
                    }
                    OSCServiceType::OSCQuery => {
                        self.osc_query_services.lock().await.insert(profile.clone());
                    }
                    _ => {}
                }
                self.registered_services
                    .lock()
                    .await
                    .insert(profile, service_info);

                Ok(())
            }
            Err(e) => {
                error!("Failed to advertise service: {:?}", e);
                Err(format!("Failed to advertise service: {}", e))
            }
        }
    }

    async fn unadvertise(&self, profile: OSCQueryServiceProfile) -> Result<(), String> {
        let mut registered = self.registered_services.lock().await;
        if let Some(service_info) = registered.remove(&profile) {
            match self.daemon.unregister(&service_info.get_fullname()) {
                Ok(_) => {
                    debug!(
                        "Unadvertising Service {} of type {} on {}:{}",
                        profile.name,
                        profile.service_type.get_service_type_string(),
                        profile.address,
                        profile.port
                    );
                    Ok(())
                }
                Err(e) => {
                    error!("Failed to unadvertise service: {:?}", e);
                    Err(format!("Failed to unadvertise service: {}", e))
                }
            }
        } else {
            debug!("Attempted to unadvertise an unregistered service.");
            Ok(())
        }
    }

    async fn get_osc_query_services(&self) -> HashSet<OSCQueryServiceProfile> {
        self.osc_query_services.lock().await.clone()
    }

    async fn get_osc_services(&self) -> HashSet<OSCQueryServiceProfile> {
        self.osc_services.lock().await.clone()
    }
}
