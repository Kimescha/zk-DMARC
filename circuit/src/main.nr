use dep::zkemail;
use dep::rsa;

global MAX_HEADER_LEN: u32 = 1024;
global BIN_SIZE: u64 = 14400; // 4-hour windows

fn string_to_u64(bytes: [u8; 10]) -> u64 {
    let mut val: u64 = 0;
    for i in 0..10 {
        let digit = bytes[i] as u64 - 48;
        val = val * 10 + digit;
    }
    val
}

fn main(
    header: [u8; MAX_HEADER_LEN],
    signature: [u8; 256],
    pubkey: rsa::RSAPublicKey,

    from_idx: u32,
    dkim_d_idx: u32,
    t_tag_idx: u32,

    pub bin_id: u64
) {

    let dkim_ok = zkemail::verify_dkim_header(header, signature, pubkey);
    assert(dkim_ok);

    let from_domain = zkemail::extract_header_field(header, "From:", from_idx, 20);
    let dkim_domain = zkemail::extract_header_field(header, "d=", dkim_d_idx, 20);
    let t_bytes = zkemail::extract_header_field(header, "t=", t_tag_idx, 10);

    assert(from_domain == dkim_domain);


    let timestamp = string_to_u64(t_bytes);
    assert(bin_id == timestamp / BIN_SIZE);
}
