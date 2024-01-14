use std::fmt::Write;

pub fn to_hex(buf: &[u8]) -> String {
    return buf.
        iter().
        fold(String::new(), |mut acc, &byte| {
            write!(
                &mut acc,
                "{:x}{:x}",
                byte >> 4,
                byte & 0xF
            ).expect("Error writing to String");

            acc
        });
}