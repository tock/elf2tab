use std::cmp;
use std::io;
use std::mem;
use std::slice;

/// Takes a value and rounds it up to be aligned % box_size
pub fn align_to(value: u32, box_size: u32) -> u32 {
    value + ((box_size - (value % box_size)) % box_size)
}

/// Takes a value and rounds it down to be aligned % box_size
pub fn align_down(value: u32, box_size: u32) -> u32 {
    value - (value % box_size)
}

/// How much needs to be added to get a value aligned % 4
pub fn amount_alignment_needed(value: u32, box_size: u32) -> u32 {
    align_to(value, box_size) - value
}

pub fn do_pad<W: io::Write>(output: &mut W, length: usize) -> io::Result<()> {
    let mut pad = length;
    let zero_buf = [0_u8; 512];
    while pad > 0 {
        let amount_to_write = cmp::min(zero_buf.len(), pad);
        pad -= output.write(&zero_buf[..amount_to_write])?;
    }
    Ok(())
}

pub unsafe fn as_byte_slice<T: Copy>(input: &T) -> &[u8] {
    slice::from_raw_parts(input as *const T as *const u8, mem::size_of::<T>())
}

#[cfg(test)]
mod test {
    use super::{align_to, amount_alignment_needed};

    #[test]
    pub fn keeps_aligned_values() {
        let result = align_to(8, 4);

        assert_eq!(result, 8);
    }

    #[test]
    pub fn aligns_to_the_next_box() {
        let result = align_to(3, 4);

        assert_eq!(result, 4);
    }

    #[test]
    pub fn aligns_to_the_next_box_with_another_box_size() {
        let result = align_to(7, 8);

        assert_eq!(result, 8);
    }

    #[test]
    pub fn computes_distance_to_lattice_point() {
        let result = amount_alignment_needed(7, 8);

        assert_eq!(result, 1);
    }
}
