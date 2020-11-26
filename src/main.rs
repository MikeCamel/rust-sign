#![deny(clippy::all)]

use config::*;
//use http::response::*;
use openssl::asn1::Asn1Time;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use std::net::{IpAddr, SocketAddr};
use warp::Filter;

#[cfg(unix)]

#[tokio::main]
async fn main() {
    let mut settings = config::Config::default();
    settings
        .merge(config::File::with_name("Server_config"))
        .unwrap()
        .merge(config::Environment::with_prefix("server"))
        .unwrap();
    
    println!("Simple signing server, written in Rust");
    println!();

    let server_address: String = settings.get("listen_address").unwrap();
    let server_port: u16 = settings.get("listen_port").unwrap();
 
    let server_socketaddr = SocketAddr::new(
        server_address.parse::<IpAddr>().unwrap(),
        server_port ,
    );
    let (server_key, server_cert) = get_credentials_bytes(&server_address);

    /*
    // POST /workload
    let workload = warp::post()
        .and(warp::path("workload"))
        //.and(warp::body::json())
        .and(warp::body::aggregate())
        .and_then(payload_launch);

    let routes = workload;
    warp::serve(routes)
        .tls()
        .cert(&server_cert)
        .key(&server_key)
        .run(listen_socketaddr)
        .await;
        */
}         

fn get_credentials_bytes(listen_addr: &str) -> (Vec<u8>, Vec<u8>) {
    let (key, cert) = generate_credentials(&listen_addr);
    (key,cert)
}

fn generate_credentials(listen_addr: &str) -> (Vec<u8>, Vec<u8>) {
    let key = Rsa::generate(2048).unwrap();
    let pkey = PKey::from_rsa(key.clone()).unwrap();

    println!("Create a certificate for {}", &listen_addr);

    let mut x509_name = openssl::x509::X509NameBuilder::new().unwrap();
    x509_name.append_entry_by_text("C", "GB").unwrap();
    x509_name.append_entry_by_text("O", "enarx-test").unwrap();
    //FIXME - we should use &listen-addr, but this fails
    x509_name
        .append_entry_by_text("subjectAltName", &listen_addr)
        .unwrap();
    //x509_name.append_entry_by_text("CN", &listen_addr).unwrap();
    x509_name.append_entry_by_text("CN", "nail").unwrap();
    let x509_name = x509_name.build();

    let mut x509_builder = openssl::x509::X509::builder().unwrap();
    if let Err(e) = x509_builder.set_not_before(&Asn1Time::days_from_now(0).unwrap()) {
        panic!("Problem creating cert {}", e)
    }
    if let Err(e) = x509_builder.set_not_after(&Asn1Time::days_from_now(7).unwrap()) {
        panic!("Problem creating cert {}", e)
    }

    x509_builder.set_subject_name(&x509_name).unwrap();
    x509_builder.set_pubkey(&pkey).unwrap();
    x509_builder.sign(&pkey, MessageDigest::sha256()).unwrap();
    let certificate = x509_builder.build();

    (
        key.private_key_to_pem().unwrap(),
        certificate.to_pem().unwrap(),
    )
}

