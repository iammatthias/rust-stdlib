//! Streaming tabular text alignment compatible with Go's `text/tabwriter`.
//!
//! The writer treats Unicode scalar values as width one, supports elastic
//! tab stops, vertical-tab soft columns, HTML and Escape filtering, and flushes
//! at form-feed section boundaries. To bound retained input and rendered
//! padding, a section is limited to 8 MiB, one million cells, and 256 aligned
//! columns. These explicit limits differ from Go's unbounded writer.
use std::io::{self, Write};

pub const FILTER_HTML: u32 = 1;
pub const STRIP_ESCAPE: u32 = 2;
pub const ALIGN_RIGHT: u32 = 4;
pub const DISCARD_EMPTY_COLUMNS: u32 = 8;
pub const TAB_INDENT: u32 = 16;
pub const DEBUG: u32 = 32;
pub const ESCAPE: u8 = 0xff;
const MAX_SECTION: usize = 8 * 1024 * 1024;
const MAX_CELLS: usize = 1_000_000;
const MAX_COLUMNS: usize = 256;

#[derive(Clone, Copy, Default)]
struct Cell {
    size: usize,
    width: usize,
    htab: bool,
}

/// A streaming text formatter. Call [`TabWriter::flush`] to emit the final
/// buffered section. Form feed flushes automatically.
pub struct TabWriter<W> {
    output: W,
    minwidth: usize,
    tabwidth: usize,
    padding: usize,
    padchar: u8,
    flags: u32,
    buf: Vec<u8>,
    pos: usize,
    cell: Cell,
    end_char: u8,
    lines: Vec<Vec<Cell>>,
    input_size: usize,
    cell_count: usize,
    failure: Option<(io::ErrorKind, String)>,
}

impl<W: Write> TabWriter<W> {
    /// Constructs a writer with Go-compatible formatting options.
    pub fn new(
        output: W,
        minwidth: usize,
        tabwidth: usize,
        padding: usize,
        padchar: u8,
        mut flags: u32,
    ) -> io::Result<TabWriter<W>> {
        if minwidth > MAX_SECTION || tabwidth > MAX_SECTION || padding > MAX_SECTION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "tabwriter: width limit exceeded",
            ));
        }
        if padchar == b'\t' {
            flags &= !ALIGN_RIGHT;
        }
        Ok(TabWriter {
            output,
            minwidth,
            tabwidth,
            padding,
            padchar,
            flags,
            buf: Vec::new(),
            pos: 0,
            cell: Cell::default(),
            end_char: 0,
            lines: vec![Vec::new()],
            input_size: 0,
            cell_count: 0,
            failure: None,
        })
    }

    fn error(&self) -> Option<io::Error> {
        self.failure
            .as_ref()
            .map(|(k, s)| io::Error::new(*k, s.clone()))
    }
    fn latch(&mut self, e: &io::Error) {
        self.failure
            .get_or_insert_with(|| (e.kind(), e.to_string()));
    }
    fn append(&mut self, bytes: &[u8]) -> io::Result<()> {
        if self.buf.len().saturating_add(bytes.len()) > MAX_SECTION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "tabwriter: section byte limit exceeded",
            ));
        }
        self.buf.extend_from_slice(bytes);
        self.cell.size += bytes.len();
        Ok(())
    }
    fn update_width(&mut self) {
        self.cell.width += rune_count(&self.buf[self.pos..]);
        self.pos = self.buf.len();
    }
    fn start_escape(&mut self, ch: u8) {
        self.end_char = match ch {
            ESCAPE => ESCAPE,
            b'<' => b'>',
            b'&' => b';',
            _ => 0,
        };
    }
    fn end_escape(&mut self) {
        match self.end_char {
            ESCAPE => {
                self.update_width();
                if self.flags & STRIP_ESCAPE == 0 {
                    self.cell.width = self.cell.width.saturating_sub(2);
                }
            }
            b'>' => {}
            b';' => self.cell.width += 1,
            _ => {}
        }
        self.pos = self.buf.len();
        self.end_char = 0;
    }
    fn terminate_cell(&mut self, htab: bool) -> io::Result<usize> {
        if self.cell_count >= MAX_CELLS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "tabwriter: cell limit exceeded",
            ));
        }
        if self.lines.last().unwrap().len() > MAX_COLUMNS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "tabwriter: column limit exceeded",
            ));
        }
        self.cell.htab = htab;
        self.lines.last_mut().unwrap().push(self.cell);
        self.cell = Cell::default();
        self.cell_count += 1;
        Ok(self.lines.last().unwrap().len())
    }
    fn reset(&mut self) {
        self.buf.clear();
        self.pos = 0;
        self.cell = Cell::default();
        self.end_char = 0;
        self.lines.clear();
        self.lines.push(Vec::new());
        self.input_size = 0;
        self.cell_count = 0;
    }
    fn flush_inner(&mut self) -> io::Result<()> {
        if self.cell.size > 0 {
            if self.end_char != 0 {
                self.end_escape();
            }
            self.terminate_cell(false)?;
        }
        let rendered = render(
            self.minwidth,
            self.tabwidth,
            self.padding,
            self.padchar,
            self.flags,
            &self.buf,
            &self.lines,
        )?;
        self.output.write_all(&rendered)?;
        self.reset();
        Ok(())
    }
    /// Emit the pending section, preserving the writer for subsequent input.
    pub fn flush(&mut self) -> io::Result<()> {
        if let Some(e) = self.error() {
            return Err(e);
        }
        match self.flush_inner().and_then(|_| self.output.flush()) {
            Ok(()) => Ok(()),
            Err(e) => {
                self.latch(&e);
                self.reset();
                Err(e)
            }
        }
    }
    /// Reinitializes the writer with new output and options, as Go's
    /// `Writer.Init` does. Unflushed text and any latched error are discarded.
    /// The new output must have the same Rust type `W` as this writer; the
    /// same width limits as [`TabWriter::new`] apply.
    pub fn init(
        &mut self,
        output: W,
        minwidth: usize,
        tabwidth: usize,
        padding: usize,
        padchar: u8,
        flags: u32,
    ) -> io::Result<&mut Self> {
        *self = TabWriter::new(output, minwidth, tabwidth, padding, padchar, flags)?;
        Ok(self)
    }
    /// Return the underlying writer after flushing buffered text.
    pub fn into_inner(mut self) -> io::Result<W> {
        self.flush()?;
        Ok(self.output)
    }
}

impl<W: Write> Write for TabWriter<W> {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        if let Some(e) = self.error() {
            return Err(e);
        }
        let result = (|| -> io::Result<()> {
            let mut n = 0usize;
            for (i, &ch) in input.iter().enumerate() {
                self.input_size += 1;
                if self.input_size > MAX_SECTION {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "tabwriter: section byte limit exceeded",
                    ));
                }
                if self.end_char == 0 {
                    match ch {
                        b'\t' | b'\x0b' | b'\n' | b'\x0c' => {
                            self.append(&input[n..i])?;
                            self.update_width();
                            n = i + 1;
                            let ncells = self.terminate_cell(ch == b'\t')?;
                            if ch == b'\n' || ch == b'\x0c' {
                                self.lines.push(Vec::new());
                                if ch == b'\x0c' || ncells == 1 {
                                    self.flush_inner()?;
                                    if ch == b'\x0c' && self.flags & DEBUG != 0 {
                                        self.output.write_all(b"---\n")?;
                                    }
                                }
                            }
                        }
                        ESCAPE => {
                            self.append(&input[n..i])?;
                            self.update_width();
                            n = i;
                            if self.flags & STRIP_ESCAPE != 0 {
                                n += 1
                            }
                            self.start_escape(ESCAPE);
                        }
                        b'<' | b'&' if self.flags & FILTER_HTML != 0 => {
                            self.append(&input[n..i])?;
                            self.update_width();
                            n = i;
                            self.start_escape(ch);
                        }
                        _ => {}
                    }
                } else if ch == self.end_char {
                    let mut j = i + 1;
                    if ch == ESCAPE && self.flags & STRIP_ESCAPE != 0 {
                        j = i
                    }
                    self.append(&input[n..j])?;
                    n = i + 1;
                    self.end_escape();
                }
            }
            self.append(&input[n..])?;
            Ok(())
        })();
        match result {
            Ok(()) => Ok(input.len()),
            Err(e) => {
                self.latch(&e);
                self.reset();
                Err(e)
            }
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        TabWriter::flush(self)
    }
}

fn append_repeat(out: &mut Vec<u8>, byte: u8, count: usize) -> io::Result<()> {
    if out.len().saturating_add(count) > MAX_SECTION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "tabwriter: output limit exceeded",
        ));
    }
    out.resize(out.len() + count, byte);
    Ok(())
}
fn append_text(out: &mut Vec<u8>, bytes: &[u8]) -> io::Result<()> {
    if out.len().saturating_add(bytes.len()) > MAX_SECTION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "tabwriter: output limit exceeded",
        ));
    }
    out.extend_from_slice(bytes);
    Ok(())
}
fn padding(
    out: &mut Vec<u8>,
    text_width: usize,
    cell_width: usize,
    tabwidth: usize,
    padchar: u8,
    use_tabs: bool,
) -> io::Result<()> {
    if padchar == b'\t' || use_tabs {
        if tabwidth == 0 {
            return Ok(());
        }
        let target = cell_width.div_ceil(tabwidth) * tabwidth;
        let n = target.saturating_sub(text_width);
        append_repeat(out, b'\t', n.div_ceil(tabwidth))
    } else {
        append_repeat(out, padchar, cell_width.saturating_sub(text_width))
    }
}
struct Renderer<'a> {
    minwidth: usize,
    tabwidth: usize,
    padding_width: usize,
    padchar: u8,
    flags: u32,
    buf: &'a [u8],
    lines: &'a [Vec<Cell>],
    out: Vec<u8>,
}

impl Renderer<'_> {
    fn write_lines(
        &mut self,
        pos0: usize,
        line0: usize,
        line1: usize,
        widths: &[usize],
    ) -> io::Result<usize> {
        let mut pos = pos0;
        for (i, line) in self.lines.iter().enumerate().take(line1).skip(line0) {
            let mut use_tabs = self.flags & TAB_INDENT != 0;
            for (j, c) in line.iter().enumerate() {
                if j > 0 && self.flags & DEBUG != 0 {
                    append_repeat(&mut self.out, b'|', 1)?;
                }
                if c.size == 0 {
                    if j < widths.len() {
                        padding(
                            &mut self.out,
                            c.width,
                            widths[j],
                            self.tabwidth,
                            self.padchar,
                            use_tabs,
                        )?;
                    }
                } else {
                    use_tabs = false;
                    if self.flags & ALIGN_RIGHT == 0 {
                        append_text(&mut self.out, &self.buf[pos..pos + c.size])?;
                        pos += c.size;
                        if j < widths.len() {
                            padding(
                                &mut self.out,
                                c.width,
                                widths[j],
                                self.tabwidth,
                                self.padchar,
                                false,
                            )?;
                        }
                    } else {
                        if j < widths.len() {
                            padding(
                                &mut self.out,
                                c.width,
                                widths[j],
                                self.tabwidth,
                                self.padchar,
                                false,
                            )?;
                        }
                        append_text(&mut self.out, &self.buf[pos..pos + c.size])?;
                        pos += c.size;
                    }
                }
            }
            if i + 1 != self.lines.len() {
                append_repeat(&mut self.out, b'\n', 1)?;
            }
        }
        Ok(pos)
    }

    fn format_range(
        &mut self,
        pos0: usize,
        line0: usize,
        line1: usize,
        widths: &mut Vec<usize>,
    ) -> io::Result<usize> {
        let mut pos = pos0;
        let column = widths.len();
        let mut start = line0;
        let mut this = line0;
        while this < line1 {
            if column >= self.lines[this].len().saturating_sub(1) {
                this += 1;
                continue;
            }
            pos = self.write_lines(pos, start, this, widths)?;
            let block_start = this;
            let mut width = self.minwidth;
            let mut discardable = true;
            while this < line1 {
                let line = &self.lines[this];
                if column >= line.len().saturating_sub(1) {
                    break;
                }
                let c = line[column];
                width = width.max(c.width.saturating_add(self.padding_width));
                if c.width > 0 || c.htab {
                    discardable = false;
                }
                this += 1;
            }
            if discardable && self.flags & DISCARD_EMPTY_COLUMNS != 0 {
                width = 0;
            }
            widths.push(width);
            pos = self.format_range(pos, block_start, this, widths)?;
            widths.pop();
            start = this;
            if this < line1 {
                this += 1;
            }
        }
        self.write_lines(pos, start, line1, widths)
    }
}
fn render(
    minwidth: usize,
    tabwidth: usize,
    padding_width: usize,
    padchar: u8,
    flags: u32,
    buf: &[u8],
    lines: &[Vec<Cell>],
) -> io::Result<Vec<u8>> {
    let mut renderer = Renderer {
        minwidth,
        tabwidth,
        padding_width,
        padchar,
        flags,
        buf,
        lines,
        out: Vec::new(),
    };
    let _ = renderer.format_range(0, 0, lines.len(), &mut Vec::new())?;
    Ok(renderer.out)
}

fn rune_count(bytes: &[u8]) -> usize {
    let mut rest = bytes;
    let mut count = 0;
    while !rest.is_empty() {
        match std::str::from_utf8(rest) {
            Ok(s) => {
                count += s.chars().count();
                break;
            }
            Err(e) => {
                let valid = e.valid_up_to();
                if valid > 0 {
                    count += std::str::from_utf8(&rest[..valid]).unwrap().chars().count();
                    rest = &rest[valid..];
                }
                if rest.is_empty() {
                    break;
                }
                // Go's utf8.RuneCount consumes one byte for each invalid RuneError.
                let n = e.error_len().unwrap_or(1).min(rest.len());
                rest = &rest[n..];
                count += 1;
            }
        }
    }
    count
}
