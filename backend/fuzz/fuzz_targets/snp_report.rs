#![no_main]

use libfuzzer_sys::fuzz_target;
use platform_enclave::{SimulatedSnp, SnpCertChain, SnpReport};

fuzz_target!(|data: &[u8]| {
    let _ = SnpReport::from_bytes(data);
    if let Ok(chain) = SnpCertChain::from_bytes(data) {
        let sim = SimulatedSnp::new();
        let _ = sim.verifier(1_000).verify(data, &chain, &[0u8; 64]);
    }
});
