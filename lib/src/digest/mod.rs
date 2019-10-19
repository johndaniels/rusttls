pub mod sha384;
pub mod sha256;

pub trait DigestAlgorithm {
    type DigestType: Digest;
    fn block_size() -> usize;
    fn result_size() -> usize;
    fn new() -> Box<Self::DigestType>;
}

pub trait Digest {
    fn update(&mut self, update_buf: &[u8]);
    fn finalize(&mut self) -> Vec<u8>;
    fn finalize_copy(&self) -> Vec<u8>;

}