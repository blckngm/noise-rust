pub fn copy_memory(input: &[u8], out: &mut [u8]) -> usize {
    out[..input.len()].copy_from_slice(input);
    input.len()
}
