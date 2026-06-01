use brotli::CompressorWriter;
use std::io::Write;

pub fn compress(input: &str) -> Vec<u8> {
    let mut compressed = Vec::new();
    let mut compressor = CompressorWriter::new(&mut compressed, 4096, 11, 22);
    compressor.write_all(input.as_bytes()).unwrap();
    compressor.flush().unwrap();
    drop(compressor);
    compressed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compress_non_empty() {
        let result = compress("Hello, World!");
        assert!(!result.is_empty());
    }

    #[test]
    fn test_compress_empty_string() {
        let result = compress("");
        // Even empty input produces some compressed output (brotli header)
        assert!(!result.is_empty());
    }

    #[test]
    fn test_compress_reduces_size_for_repetitive_data() {
        let input = "a".repeat(10000);
        let result = compress(&input);
        assert!(result.len() < input.len());
    }

    #[test]
    fn test_compress_different_inputs_different_outputs() {
        let result1 = compress("Hello");
        let result2 = compress("World");
        assert_ne!(result1, result2);
    }
}
