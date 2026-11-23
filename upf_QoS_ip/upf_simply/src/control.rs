use std::net::Ipv4Addr;
use serde::Deserialize;
use serde::Serialize;
use tokio::net::UdpSocket;
use upf_simply_common::{BucketParam, FAR_DROP, FAR_FORWARD, Far, Pdr, Qer, QerState};
use std::sync::Arc;
use std::sync::Mutex;
use aya::maps::{HashMap, PerCpuValues};
use aya::maps::PerCpuHashMap;


fn default_burst_bytes() -> u64 {
    15_000
}
fn default_true() -> bool {
    true
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FarAction {
    #[default]
    Forward,
    Drop,
}

#[derive(Debug, Deserialize)]
pub struct QosParams {
    pub qer_id: u32,
    pub qfi: u8,
    pub gbr_mbps: u64,
    pub mbr_mbps: u64,
    #[serde(default = "default_burst_bytes")]
    pub burst_bytes: u64,
}

#[derive(Clone)]
pub struct ControlState {
    pub ul_pdr_map: Arc<Mutex<HashMap<aya::maps::MapData, u32, Pdr>>>,
    pub dl_pdr_map: Arc<Mutex<HashMap<aya::maps::MapData, u32, Pdr>>>,
    pub far_map: Arc<Mutex<HashMap<aya::maps::MapData, u32, Far>>>,
    pub qer_map: Arc<Mutex<HashMap<aya::maps::MapData, u32, Qer>>>,
    pub qer_state_map: Arc<Mutex<PerCpuHashMap<aya::maps::MapData, u32, QerState>>>,
    pub num_cpus: u64,
    pub cpu_div: u64,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum ControlCommand {

    AddUplink {
        teid: u32,
        far_id: u32,
        #[serde(default)]
        far_action: FarAction,
        #[serde(default = "default_true")]
        outer_hdr_removed: bool,
        qos: Option<QosParams>,
    },

    AddDownlink {
        ue_ip: Ipv4Addr,
        far_id: u32,
        #[serde(default)]
        far_action: FarAction,
        peer_ip: Ipv4Addr,
        peer_teid: u32,
        local_ip: Ipv4Addr,
        #[serde(default = "default_true")]
        outer_hdr_creation: bool,
        qos: Option<QosParams>,
    },

    UpdateQer {
        qer_id: u32,
        qfi: u8,
        #[serde(default)]
        gbr_ul_mbps: u64,
        #[serde(default)]
        mbr_ul_mbps: u64,
        #[serde(default)]
        gbr_dl_mbps: u64,
        #[serde(default)]
        mbr_dl_mbps: u64,
        #[serde(default = "default_burst_bytes")]
        burst_bytes: u64,
    },

    DeleteUplink {
        teid: u32,
    },

    DeleteDownlink {
        ue_ip: Ipv4Addr,
    },
}

#[derive(Serialize)]
struct ControlResponse {
    ok: bool,
    message: String
}

pub fn apply_command (state: &ControlState, cmd: ControlCommand) -> anyhow::Result<()> {

    match cmd {

        ControlCommand::AddUplink { teid, far_id, far_action, outer_hdr_removed, qos } => {
            let qer_id;
            match qos {
                Some(q) => {
                    if q.qer_id != 0 && (q.gbr_mbps <= q.mbr_mbps && q.mbr_mbps > 0) {
                        state.qer_state_map.lock().unwrap().insert(q.qer_id, zero_qer_state(state.num_cpus)?, 0)?;
                        state.qer_map.lock().unwrap().insert(q.qer_id, Qer {qfi: q.qfi, cir_ul: make_bucket(q.gbr_mbps, q.burst_bytes, state.cpu_div),
                                                                                        pir_ul: make_bucket(q.mbr_mbps, q.burst_bytes, state.cpu_div),
                                                                                        cir_dl: make_bucket(0, q.burst_bytes, state.cpu_div),
                                                                                        pir_dl: make_bucket(0, q.burst_bytes, state.cpu_div)},                                                                                    
                                                                                        0)?;
                        qer_id = q.qer_id;
                    } else {
                        anyhow::bail!("Uno o più parametri QoS errati")
                    }
                }
                None => {qer_id = 0;},
            }

            state.far_map.lock().unwrap().insert(far_id, Far { action: far_action_to_u8(&far_action),
                                                                        outer_hdr_creation: 0,
                                                                        _pad: [0; 2],
                                                                        peer_ip: 0, peer_teid: 0, local_ip: 0}, 0)?;
            state.ul_pdr_map.lock().unwrap().insert(teid, Pdr{ far_id: far_id, qer_id: qer_id, 
                                                                        outer_hdr_removed: outer_hdr_removed.into(), _pad: [0; 3]}, 0)?;
        }

        ControlCommand::AddDownlink { ue_ip, far_id, far_action, peer_ip, peer_teid, local_ip, outer_hdr_creation, qos } => {
            let qer_id;
            match qos {
                Some(q) => {
                    if q.qer_id != 0 && (q.gbr_mbps <= q.mbr_mbps && q.mbr_mbps > 0) {
                        state.qer_state_map.lock().unwrap().insert(q.qer_id, zero_qer_state(state.num_cpus)?, 0)?;
                        state.qer_map.lock().unwrap().insert(q.qer_id, Qer {qfi: q.qfi, cir_ul: make_bucket(0, q.burst_bytes, state.cpu_div),
                                                                                        pir_ul: make_bucket(0, q.burst_bytes, state.cpu_div),
                                                                                        cir_dl: make_bucket(q.gbr_mbps, q.burst_bytes, state.cpu_div),
                                                                                        pir_dl: make_bucket(q.mbr_mbps, q.burst_bytes, state.cpu_div)},                                                                                    
                                                                                        0)?;
                        qer_id = q.qer_id;
                    } else {
                        anyhow::bail!("Uno o più parametri QoS errati")
                    }
                }
                None => qer_id = 0,
            }

            state.far_map.lock().unwrap().insert(far_id, Far { action: far_action_to_u8(&far_action),
                                                                        outer_hdr_creation: outer_hdr_creation.into(),
                                                                        _pad: [0; 2],
                                                                        peer_ip: peer_ip.to_bits(), 
                                                                        peer_teid: peer_teid, local_ip: local_ip.to_bits()}, 0)?;
            state.dl_pdr_map.lock().unwrap().insert(ue_ip.to_bits(), Pdr{ far_id: far_id, qer_id: qer_id, 
                                                                        outer_hdr_removed: 0, _pad: [0; 3]}, 0)?;
            
        }

        ControlCommand::UpdateQer { qer_id, qfi, gbr_ul_mbps, mbr_ul_mbps, gbr_dl_mbps, mbr_dl_mbps, burst_bytes } => {
            if qer_id != 0 && ((gbr_ul_mbps <= mbr_ul_mbps && gbr_dl_mbps <= mbr_dl_mbps) && (mbr_ul_mbps > 0 || mbr_dl_mbps > 0 )) {
                if state.qer_state_map.lock().unwrap().get(&qer_id, 0).is_err() {
                    state.qer_state_map.lock().unwrap().insert(qer_id, zero_qer_state(state.num_cpus)?, 0)?;
                } 
                state.qer_map.lock().unwrap().insert(qer_id, Qer {qfi: qfi, cir_ul: make_bucket(gbr_ul_mbps, burst_bytes, state.cpu_div),
                                                                                    pir_ul: make_bucket(mbr_ul_mbps, burst_bytes, state.cpu_div),
                                                                                    cir_dl: make_bucket(gbr_dl_mbps, burst_bytes, state.cpu_div),
                                                                                    pir_dl: make_bucket(mbr_dl_mbps, burst_bytes, state.cpu_div)},                                                                                    
                                                                                    0)?;
            } else {
                anyhow::bail!("Uno o più parametri QoS errati")
            }
        }

        ControlCommand::DeleteUplink { teid } => {
            if state.ul_pdr_map.lock().unwrap().get(&teid, 0).is_err() {
                anyhow::bail!("PDR NON TROVATA")
            } else {
                state.ul_pdr_map.lock().unwrap().remove(&teid)?;
            }
        }

        ControlCommand::DeleteDownlink { ue_ip } => {
            if state.dl_pdr_map.lock().unwrap().get(&ue_ip.to_bits(), 0).is_err() {
                anyhow::bail!("PDR NON TROVATA")
            } else {
                state.dl_pdr_map.lock().unwrap().remove(&ue_ip.to_bits())?;
            }
        }
    }


    Ok(())
}

pub async  fn run_control_plane ( socket: UdpSocket, state: ControlState ) {
    
    if let Ok(addr) = socket.local_addr() {
        println!("[CP]: in ascolto on: {:?}", addr);
    }
    
    let mut buffer = vec![0u8; 4096];
    loop {
        match socket.recv_from(&mut buffer).await {
            Err(e) => {
                eprintln!("{}",e);
                continue;
            }
            Ok((len, peer_addr)) => {
                let response: ControlResponse;
                match serde_json::from_slice::<ControlCommand>(&buffer[..len]) {
                    Err(e) => {
                        response = ControlResponse {
                            ok: false,
                            message: format!("{}", e.to_string())
                        };
                    }
                    Ok(cmd) => {
                        match apply_command(&state, cmd) {
                            Ok(_) => {
                                response = ControlResponse {
                                    ok: true,
                                    message: format!("[CP]: Comando eseguito correttamente"),
                                };
                            }
                            Err(e) => {
                                response = ControlResponse {
                                    ok: false,
                                    message: format!("[CP]: {}", e.to_string())
                                };
                            }
                        }
                    }
                }
                println!("{}", response.message);
                if let Ok(mut payload) = serde_json::to_vec(&response) {
                    payload.push(b'\n');
                    if let Err(e) = socket.send_to(&payload, peer_addr).await {
                        eprintln!("{}", e);
                    }
                }            
            }
        }

    }
}

// Calcolo del costo temporale (in nanosecondi) di un byte
fn calc_ns_per_byte_scaled(bits_per_sec: u64) -> u64 {
        if bits_per_sec == 0 { return 0; } // Gestione dei flussi non-QoS
        let bytes_per_sec = bits_per_sec / 8;
    // Moltiplica 1 secondo (10^9 ns) per 2^30 prima di dividere per i Byte/s
        (1_000_000_000u64 << 30) / bytes_per_sec
}

// Calcolo della tolleranza di burst in nanosecondi
fn calc_burst_tolerance_ns(bits_per_sec: u64, burst_bytes: u64) -> u64 {
        burst_bytes * calc_ns_per_byte_scaled(bits_per_sec) >> 30
}
 
fn make_bucket( rate_mbps: u64, burst_bytes: u64, cpu_div: u64) -> BucketParam {

    if rate_mbps == 0 {
        return BucketParam { ns_per_byte: 0, burst_tolerance_ns: 0 }
    } else {
        let rate_bps = rate_mbps * 1_000_000; // in bit/s
        let rate_bps_per_cpu = rate_bps /cpu_div;
        return BucketParam { ns_per_byte: calc_ns_per_byte_scaled(rate_bps_per_cpu), burst_tolerance_ns: calc_burst_tolerance_ns(rate_bps_per_cpu, burst_bytes) }        
    }
}

fn far_action_to_u8 (action: &FarAction) -> u8 {
    match action {
        FarAction::Forward => return FAR_FORWARD,
        FarAction::Drop => return FAR_DROP,
    }
}

fn zero_qer_state (num_cpus: u64) -> anyhow::Result<PerCpuValues<QerState>> {
    return Ok(PerCpuValues::try_from((0..num_cpus as usize).map(|_| QerState { tat_cir_dl: 0, tat_pir_dl: 0, tat_cir_ul: 0, tat_pir_ul: 0 }).collect::<Vec<_>>())?)
}