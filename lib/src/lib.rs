pub mod client;
mod eliptic_curve;
mod digest;
mod hmac;
mod diffie_helman;
mod cipher;
mod messages;
mod codec;
mod signature;

#[cfg(test)]
mod tests {
    #[test]
    fn test_connect() {
        //super::tls::connect();
    }
}
