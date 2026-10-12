//! Splits a fuzz input into socket reads, so that every target also
//! explores how the server bytes are segmented.

/// The reads carved out of a fuzz input.
pub struct Reads<'a> {
    data: &'a [u8],
    size: usize,
}

impl<'a> Reads<'a> {
    /// Takes the read size from the first byte, from 1 to 1954 octets.
    pub fn new(data: &'a [u8]) -> Self {
        match data.split_first() {
            Some((first, data)) => Self {
                data,
                size: (*first as usize % 64) * 31 + 1,
            },
            None => Self { data, size: 1 },
        }
    }

    /// The next read, empty (EOF) once the input is used up.
    pub fn next(&mut self) -> &'a [u8] {
        let take = self.size.min(self.data.len());
        let (chunk, data) = self.data.split_at(take);
        self.data = data;
        chunk
    }
}
