//! Shannon entropy: a measure of how "random" a block of bytes looks.
//!
//! The result ranges from 0.0 (every byte identical) to 8.0 (every byte value
//! equally likely). Normal machine code sits around 5–6.5. Compressed or
//! encrypted data sits close to 8, which is why a high-entropy code section is
//! a classic sign that a binary has been packed to hide what it really does.

/// Returns the Shannon entropy of `data`, in bits per byte.
pub fn shannon(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    // Count how many times each of the 256 possible byte values appears.
    let mut counts = [0u64; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }

    let len = data.len() as f64;
    counts
        .iter()
        .filter(|&&count| count > 0)
        .map(|&count| {
            let p = count as f64 / len;
            -p * p.log2()
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uniform_bytes_have_zero_entropy() {
        assert_eq!(shannon(&[0x41; 1000]), 0.0);
    }

    #[test]
    fn every_byte_once_is_maximum_entropy() {
        let all: Vec<u8> = (0..=255).collect();
        assert!((shannon(&all) - 8.0).abs() < 1e-9);
    }

    #[test]
    fn empty_input_is_zero() {
        assert_eq!(shannon(&[]), 0.0);
    }
}
