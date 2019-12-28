struct Encoder<'b> {
    buffer: &'b mut [u8],
}

impl<'b> Encoder<'b> {
    fn new(buffer: &'b mut [u8]) -> Self {
        Self { buffer }
    }

    fn map<F>(&mut self, f: F) -> {
        self.buffer[0] = 0xa0 + len(map);
        f(self.buffer[1:]);
    }
}
