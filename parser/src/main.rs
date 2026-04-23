use mailparse::parse_mail;
use serde::Serialize;
use std::fs;

#[derive(Serialize)]
struct ProverInputs {
    header: [u8; 1024],
    signature: [u8; 256],
    pubkey: serde_json::Value,
    from_idx: usize,
    dkim_d_idx: usize,
    t_tag_idx: usize,
    bin_id: u64,
}

fn main() {
    let eml_data = fs::read("../test_email.eml").expect("Need an .eml file");
    let mail = parse_mail(&eml_data).expect("Invalid email format");

    let mut header_block = String::new();
    let mut f_idx = 0;
    let mut d_idx = 0;
    let mut t_idx = 0;
    let mut timestamp: u64 = 0;

    for h in &mail.headers {
        let key = h.get_key().to_lowercase();
        let val = h.get_value();
        
        if key == "from" {
            f_idx = header_block.len() + 5; 
        }
        if key == "dkim-signature" {

            if let Some(pos) = val.find("d=") { d_idx = header_block.len() + key.len() + 2 + pos + 2; }
            if let Some(pos) = val.find("t=") { 
                t_idx = header_block.len() + key.len() + 2 + pos + 2;
                timestamp = val[pos+2..pos+12].parse().unwrap_or(0);
            }
        }
        header_block.push_str(&format!("{}:{}\r\n", key, val));
    }

    let mut header_bytes = [0u8; 1024];
    header_bytes[..header_block.len().min(1024)].copy_from_slice(&header_block.as_bytes()[..header_block.len().min(1024)]);

    let inputs = ProverInputs {
        header: header_bytes,
        signature: [0u8; 256], 
        pubkey: serde_json::json!({}), 
        from_idx: f_idx,
        dkim_d_idx: d_idx,
        t_tag_idx: t_idx,
        bin_id: timestamp / 14400,
    };

    fs::write("../circuit/Prover.toml", toml::to_string(&inputs).unwrap()).unwrap();
    println!("Generated Prover.toml for Noir!");
}
