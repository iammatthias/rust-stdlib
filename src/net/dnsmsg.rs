//! A minimal DNS wire codec, the subset of `golang.org/x/net/dns/dnsmessage`
//! that Go's pure resolver uses (see NOTICE): header, question, resource
//! headers, compressed names, and the A, AAAA, CNAME, MX, NS, PTR, SRV and
//! TXT bodies, with the same strictness about malformed messages.
use std::sync::Arc;

pub(crate) const TYPE_A: u16 = 1;
pub(crate) const TYPE_NS: u16 = 2;
pub(crate) const TYPE_CNAME: u16 = 5;
pub(crate) const TYPE_PTR: u16 = 12;
pub(crate) const TYPE_MX: u16 = 15;
pub(crate) const TYPE_TXT: u16 = 16;
pub(crate) const TYPE_AAAA: u16 = 28;
pub(crate) const TYPE_SRV: u16 = 33;
pub(crate) const TYPE_OPT: u16 = 41;
pub(crate) const CLASS_INET: u16 = 1;

pub(crate) const RCODE_SUCCESS: u16 = 0;
pub(crate) const RCODE_SERVER_FAILURE: u16 = 2;
pub(crate) const RCODE_NAME_ERROR: u16 = 3;

/// A packing or parsing failure; only its existence matters to the resolver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MsgError {
    /// `dnsmessage.ErrSectionDone`.
    SectionDone,
    /// Any other error.
    Bad,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct Header {
    pub id: u16,
    pub response: bool,
    pub authoritative: bool,
    pub truncated: bool,
    pub recursion_available: bool,
    pub rcode: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Question {
    pub name: Vec<u8>,
    pub typ: u16,
    pub class: u16,
}

#[derive(Clone, Debug)]
pub(crate) struct ResourceHeader {
    pub name: Vec<u8>,
    pub typ: u16,
    pub ttl: u32,
}

impl ResourceHeader {
    /// `ResourceHeader.ExtendedRCode`.
    pub(crate) fn extended_rcode(&self, rcode: u16) -> u16 {
        if self.ttl & 0x00ff_0000 == 0 {
            ((self.ttl >> 24) << 4) as u16 | rcode
        } else {
            rcode
        }
    }
}

/// Builds the request for `q` as `(id, udp_message, tcp_message)`; the TCP
/// form carries the two-byte length prefix. Mirrors Go's `newRequest`.
pub(crate) fn request(
    id: u16,
    q: &Question,
    ad: bool,
    edns0: bool,
) -> Result<(Vec<u8>, Vec<u8>), MsgError> {
    let mut m = vec![0u8, 0u8];
    m.extend_from_slice(&id.to_be_bytes());
    let mut bits: u16 = 0x0100;
    if ad {
        bits |= 0x0020;
    }
    m.extend_from_slice(&bits.to_be_bytes());
    m.extend_from_slice(&1u16.to_be_bytes());
    m.extend_from_slice(&0u16.to_be_bytes());
    m.extend_from_slice(&0u16.to_be_bytes());
    m.extend_from_slice(&(edns0 as u16).to_be_bytes());
    pack_name(&mut m, &q.name)?;
    m.extend_from_slice(&q.typ.to_be_bytes());
    m.extend_from_slice(&q.class.to_be_bytes());
    if edns0 {
        m.push(0);
        m.extend_from_slice(&TYPE_OPT.to_be_bytes());
        m.extend_from_slice(&1232u16.to_be_bytes());
        m.extend_from_slice(&0u32.to_be_bytes());
        m.extend_from_slice(&0u16.to_be_bytes());
    }
    let l = m.len() - 2;
    m[0] = (l >> 8) as u8;
    m[1] = l as u8;
    let udp = m[2..].to_vec();
    Ok((udp, m))
}

fn pack_name(msg: &mut Vec<u8>, name: &[u8]) -> Result<(), MsgError> {
    if name.len() > 254 || name.last() != Some(&b'.') {
        return Err(MsgError::Bad);
    }
    if name == b"." {
        msg.push(0);
        return Ok(());
    }
    let mut begin = 0;
    for (i, &c) in name.iter().enumerate() {
        if c == b'.' {
            if i - begin >= 64 || i == begin {
                return Err(MsgError::Bad);
            }
            msg.push((i - begin) as u8);
            msg.extend_from_slice(&name[begin..i]);
            begin = i + 1;
        }
    }
    msg.push(0);
    Ok(())
}

fn u16_at(msg: &[u8], off: usize) -> Result<(u16, usize), MsgError> {
    if off + 2 > msg.len() {
        return Err(MsgError::Bad);
    }
    Ok((u16::from_be_bytes([msg[off], msg[off + 1]]), off + 2))
}

fn u32_at(msg: &[u8], off: usize) -> Result<(u32, usize), MsgError> {
    if off + 4 > msg.len() {
        return Err(MsgError::Bad);
    }
    Ok((
        u32::from_be_bytes([msg[off], msg[off + 1], msg[off + 2], msg[off + 3]]),
        off + 4,
    ))
}

/// Unpacks a possibly compressed name into presentation form with a trailing dot.
fn unpack_name(msg: &[u8], off: usize) -> Result<(Vec<u8>, usize), MsgError> {
    let mut cur = off;
    let mut new_off = off;
    let mut ptr = 0;
    let mut name: Vec<u8> = Vec::new();
    loop {
        if cur >= msg.len() {
            return Err(MsgError::Bad);
        }
        let c = msg[cur] as usize;
        cur += 1;
        match c & 0xC0 {
            0x00 => {
                if c == 0 {
                    break;
                }
                let end = cur + c;
                if end > msg.len() {
                    return Err(MsgError::Bad);
                }
                if msg[cur..end].contains(&b'.') {
                    return Err(MsgError::Bad);
                }
                if name.len() + (end - cur) >= 254 {
                    return Err(MsgError::Bad);
                }
                name.extend_from_slice(&msg[cur..end]);
                name.push(b'.');
                cur = end;
            }
            0xC0 => {
                if cur >= msg.len() {
                    return Err(MsgError::Bad);
                }
                let c1 = msg[cur] as usize;
                cur += 1;
                if ptr == 0 {
                    new_off = cur;
                }
                ptr += 1;
                if ptr > 10 {
                    return Err(MsgError::Bad);
                }
                cur = (c ^ 0xC0) << 8 | c1;
            }
            _ => return Err(MsgError::Bad),
        }
    }
    if name.is_empty() {
        name.push(b'.');
    }
    if ptr == 0 {
        new_off = cur;
    }
    Ok((name, new_off))
}

fn skip_name(msg: &[u8], off: usize) -> Result<usize, MsgError> {
    let mut new_off = off;
    loop {
        if new_off >= msg.len() {
            return Err(MsgError::Bad);
        }
        let c = msg[new_off] as usize;
        new_off += 1;
        match c & 0xC0 {
            0x00 => {
                if c == 0 {
                    break;
                }
                new_off += c;
                if new_off > msg.len() {
                    return Err(MsgError::Bad);
                }
            }
            0xC0 => {
                new_off += 1;
                break;
            }
            _ => return Err(MsgError::Bad),
        }
    }
    Ok(new_off)
}

/// The incremental message parser (`dnsmessage.Parser`), cloneable to
/// preserve a position.
#[derive(Clone, Debug)]
pub(crate) struct Parser {
    msg: Arc<Vec<u8>>,
    counts: [u16; 4],
    section: usize,
    off: usize,
    index: usize,
    res_valid: bool,
    res_offset: usize,
    res_length: u16,
}

impl Parser {
    /// The zero `dnsmessage.Parser`: not started, so every read fails.
    pub(crate) fn unstarted() -> Parser {
        Parser {
            msg: Arc::new(Vec::new()),
            counts: [0; 4],
            section: 0,
            off: 0,
            index: 0,
            res_valid: false,
            res_offset: 0,
            res_length: 0,
        }
    }

    /// `Parser.Start`.
    pub(crate) fn start(msg: &[u8]) -> Result<(Parser, Header), MsgError> {
        if msg.len() < 12 {
            return Err(MsgError::Bad);
        }
        let id = u16::from_be_bytes([msg[0], msg[1]]);
        let bits = u16::from_be_bytes([msg[2], msg[3]]);
        let counts = [
            u16::from_be_bytes([msg[4], msg[5]]),
            u16::from_be_bytes([msg[6], msg[7]]),
            u16::from_be_bytes([msg[8], msg[9]]),
            u16::from_be_bytes([msg[10], msg[11]]),
        ];
        let h = Header {
            id,
            response: bits & 0x8000 != 0,
            authoritative: bits & 0x0400 != 0,
            truncated: bits & 0x0200 != 0,
            recursion_available: bits & 0x0080 != 0,
            rcode: bits & 0xF,
        };
        Ok((
            Parser {
                msg: Arc::new(msg.to_vec()),
                counts,
                section: 0,
                off: 12,
                index: 0,
                res_valid: false,
                res_offset: 0,
                res_length: 0,
            },
            h,
        ))
    }

    fn check_advance(&mut self, sec: usize) -> Result<(), MsgError> {
        if self.section < sec {
            return Err(MsgError::Bad);
        }
        if self.section > sec {
            return Err(MsgError::SectionDone);
        }
        self.res_valid = false;
        if self.index == self.counts[sec] as usize {
            self.index = 0;
            self.section += 1;
            return Err(MsgError::SectionDone);
        }
        Ok(())
    }

    /// `Parser.Question`.
    pub(crate) fn question(&mut self) -> Result<Question, MsgError> {
        self.check_advance(0)?;
        let (name, off) = unpack_name(&self.msg, self.off)?;
        let (typ, off) = u16_at(&self.msg, off)?;
        let (class, off) = u16_at(&self.msg, off)?;
        self.off = off;
        self.index += 1;
        Ok(Question { name, typ, class })
    }

    /// `Parser.SkipQuestion`.
    pub(crate) fn skip_question(&mut self) -> Result<(), MsgError> {
        self.check_advance(0)?;
        let off = skip_name(&self.msg, self.off)?;
        let (_, off) = u16_at(&self.msg, off)?;
        let (_, off) = u16_at(&self.msg, off)?;
        self.off = off;
        self.index += 1;
        Ok(())
    }

    fn resource_header(&mut self, sec: usize) -> Result<ResourceHeader, MsgError> {
        if self.res_valid {
            self.off = self.res_offset;
        }
        self.check_advance(sec)?;
        let (name, off) = unpack_name(&self.msg, self.off)?;
        let (typ, off) = u16_at(&self.msg, off)?;
        let (_class, off) = u16_at(&self.msg, off)?;
        let (ttl, off) = u32_at(&self.msg, off)?;
        let (length, off) = u16_at(&self.msg, off)?;
        self.res_valid = true;
        self.res_offset = self.off;
        self.res_length = length;
        self.off = off;
        Ok(ResourceHeader { name, typ, ttl })
    }

    fn skip_resource(&mut self, sec: usize) -> Result<(), MsgError> {
        if self.res_valid && self.section == sec {
            let new_off = self.off + self.res_length as usize;
            if new_off > self.msg.len() {
                return Err(MsgError::Bad);
            }
            self.off = new_off;
            self.res_valid = false;
            self.index += 1;
            return Ok(());
        }
        self.check_advance(sec)?;
        let off = skip_name(&self.msg, self.off)?;
        let (_, off) = u16_at(&self.msg, off)?;
        let (_, off) = u16_at(&self.msg, off)?;
        let (_, off) = u32_at(&self.msg, off)?;
        let (length, off) = u16_at(&self.msg, off)?;
        let new_off = off + length as usize;
        if new_off > self.msg.len() {
            return Err(MsgError::Bad);
        }
        self.off = new_off;
        self.index += 1;
        Ok(())
    }

    /// `Parser.AnswerHeader`.
    pub(crate) fn answer_header(&mut self) -> Result<ResourceHeader, MsgError> {
        self.resource_header(1)
    }

    /// `Parser.SkipAnswer`.
    pub(crate) fn skip_answer(&mut self) -> Result<(), MsgError> {
        self.skip_resource(1)
    }

    /// `Parser.SkipAllAnswers`.
    pub(crate) fn skip_all_answers(&mut self) {
        while self.skip_answer().is_ok() {}
    }

    /// `Parser.SkipAllAuthorities`.
    pub(crate) fn skip_all_authorities(&mut self) {
        while self.skip_resource(2).is_ok() {}
    }

    /// `Parser.AdditionalHeader`.
    pub(crate) fn additional_header(&mut self) -> Result<ResourceHeader, MsgError> {
        self.resource_header(3)
    }

    /// `Parser.SkipAdditional`.
    pub(crate) fn skip_additional(&mut self) -> Result<(), MsgError> {
        self.skip_resource(3)
    }

    // Position the cursor at the body of the current resource and return
    // `(body_offset, body_end)`.
    fn body(&mut self) -> (usize, usize) {
        let start = self.off;
        (start, start + self.res_length as usize)
    }

    fn finish_body(&mut self, end: usize) {
        self.res_valid = false;
        self.off = end;
        self.index += 1;
    }

    /// `Parser.AResource`.
    pub(crate) fn a_resource(&mut self) -> Result<[u8; 4], MsgError> {
        let (s, e) = self.body();
        if s + 4 > self.msg.len() {
            return Err(MsgError::Bad);
        }
        let a = [
            self.msg[s],
            self.msg[s + 1],
            self.msg[s + 2],
            self.msg[s + 3],
        ];
        self.finish_body(e);
        Ok(a)
    }

    /// `Parser.AAAAResource`.
    pub(crate) fn aaaa_resource(&mut self) -> Result<[u8; 16], MsgError> {
        let (s, e) = self.body();
        if s + 16 > self.msg.len() {
            return Err(MsgError::Bad);
        }
        let mut a = [0u8; 16];
        a.copy_from_slice(&self.msg[s..s + 16]);
        self.finish_body(e);
        Ok(a)
    }

    /// `Parser.CNAMEResource`, `NSResource` and `PTRResource`: one name.
    pub(crate) fn name_resource(&mut self) -> Result<Vec<u8>, MsgError> {
        let (s, e) = self.body();
        let (name, _) = unpack_name(&self.msg, s)?;
        self.finish_body(e);
        Ok(name)
    }

    /// `Parser.MXResource`.
    pub(crate) fn mx_resource(&mut self) -> Result<(u16, Vec<u8>), MsgError> {
        let (s, e) = self.body();
        let (pref, off) = u16_at(&self.msg, s)?;
        let (name, _) = unpack_name(&self.msg, off)?;
        self.finish_body(e);
        Ok((pref, name))
    }

    /// `Parser.SRVResource`: `(priority, weight, port, target)`.
    pub(crate) fn srv_resource(&mut self) -> Result<(u16, u16, u16, Vec<u8>), MsgError> {
        let (s, e) = self.body();
        let (priority, off) = u16_at(&self.msg, s)?;
        let (weight, off) = u16_at(&self.msg, off)?;
        let (port, off) = u16_at(&self.msg, off)?;
        let (target, _) = unpack_name(&self.msg, off)?;
        self.finish_body(e);
        Ok((priority, weight, port, target))
    }

    /// `Parser.TXTResource`: the character strings.
    pub(crate) fn txt_resource(&mut self) -> Result<Vec<Vec<u8>>, MsgError> {
        let (mut off, e) = self.body();
        let length = self.res_length;
        let mut txts = Vec::new();
        let mut n: u16 = 0;
        while n < length {
            if off >= self.msg.len() {
                return Err(MsgError::Bad);
            }
            let l = self.msg[off] as usize;
            let end = off + 1 + l;
            if end > self.msg.len() {
                return Err(MsgError::Bad);
            }
            if length - n < (l as u16).wrapping_add(1) {
                return Err(MsgError::Bad);
            }
            n += l as u16 + 1;
            txts.push(self.msg[off + 1..end].to_vec());
            off = end;
        }
        self.finish_body(e);
        Ok(txts)
    }
}
