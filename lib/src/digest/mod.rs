pub mod sha384;
pub mod sha256;

#[derive(Clone, Copy)]
pub enum DigestAlgorithm {
    Sha256,
    Sha384,
}

impl DigestAlgorithm {
    fn config(&self) -> Box<dyn DigestAlgorithmConfig> {
        match self {
            DigestAlgorithm::Sha256 => Box::new(sha256::Sha256AlgorithmConfig {}),
            DigestAlgorithm::Sha384 => Box::new(sha384::Sha384AlgorithmConfig {}),
        }
    }
    pub fn block_size(&self) -> usize {
        self.config().block_size()
    }

    pub fn result_size(&self) -> usize {
        self.config().result_size()
    }

    pub fn create(&self) -> Box<dyn Digest> {
        self.config().create()
    }
}

/// Internal trait created for each digest type and used by DigestAlgorithm above
/// so that we don't have to pass trait objects everywhere.
trait DigestAlgorithmConfig  {
    fn block_size(&self) -> usize;
    fn result_size(&self) -> usize;
    fn create(&self) -> Box<dyn Digest>;
}

pub trait Digest {
    fn update(&mut self, update_buf: &[u8]);
    fn finalize(&mut self) -> Vec<u8>;
    fn finalize_copy(&self) -> Vec<u8>;
}