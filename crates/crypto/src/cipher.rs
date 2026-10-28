//! Go's `crypto/cipher`: block cipher modes and AEADs over reviewed RustCrypto crates.
//!
//! The traits mirror Go's interfaces ([`Block`], [`Stream`], [`BlockMode`],
//! [`Aead`]). The modes themselves are the `cbc`, `cfb-mode`, `ctr`, `ofb` and
//! `aes-gcm` crates; this module only translates Go's constructors, buffer
//! rules and messages.
//!
//! # Deviations from Go
//!
//! - Go panics on caller mistakes (a wrong IV or nonce length, a short output
//!   buffer, input that is not whole blocks). Here those are `Err(`[`Error`]`)`
//!   carrying Go's panic message, so a caller can match on it.
//! - Rust's borrow rules forbid the partial buffer overlaps Go rejects with
//!   "invalid buffer overlap", so those errors cannot occur. The `*_in_place`
//!   methods cover Go's exact-overlap idiom (`dst` equal to `src`) and
//!   [`Aead::seal`] / [`Aead::open`] append to a `Vec` like Go's `dst` argument.
//! - Modes accept any [`Block`] whose block size is 8 or 16 bytes (every cipher
//!   Go ships, and every block cipher in common use); other sizes are refused
//!   with an error. GCM additionally supports the nonce sizes listed in
//!   [`GCM_NONCE_SIZES`], because the `aes-gcm` crate fixes them at compile time.

use std::any::Any;
use std::borrow::Cow;
use std::fmt;
use std::io;
use std::marker::PhantomData;

use ::aes::cipher::{
    array::{Array, ArraySize},
    consts::{U1, U16, U8},
    typenum::Unsigned,
    Block as CipherBlock, BlockCipherDecBackend, BlockCipherDecClosure, BlockCipherDecrypt,
    BlockCipherEncBackend, BlockCipherEncClosure, BlockCipherEncrypt, BlockModeDecrypt,
    BlockModeEncrypt, BlockSizeUser, InOut, InOutBuf, InnerIvInit, ParBlocksSizeUser, StreamCipher,
    StreamCipherCoreWrapper,
};
use ::aes_gcm::{AeadInOut, AesGcm};

/// The error behind every condition where Go panics or fails in
/// `crypto/cipher`; its text is Go's.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Error(Cow<'static, str>);

impl Error {
    pub(crate) const fn new(message: &'static str) -> Self {
        Error(Cow::Borrowed(message))
    }

    fn owned(message: String) -> Self {
        Error(Cow::Owned(message))
    }

    /// The message, exactly as Go prints it.
    pub fn message(&self) -> &str {
        &self.0
    }

    /// Reports whether this is Go's `errOpen`, "cipher: message authentication failed".
    pub fn is_authentication_failure(&self) -> bool {
        *self == ERR_OPEN
    }
}

const ERR_OPEN: Error = Error::new("cipher: message authentication failed");

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

/// Go's `cipher.Block`: a block cipher of one fixed block size.
pub trait Block {
    /// Returns the cipher's block size in bytes.
    fn block_size(&self) -> usize;

    /// Encrypts the first block of `src` into the first block of `dst`.
    /// Fails, with Go's panic message, when either is shorter than a block.
    fn encrypt(&self, dst: &mut [u8], src: &[u8]) -> Result<(), Error>;

    /// Decrypts the first block of `src` into the first block of `dst`.
    fn decrypt(&self, dst: &mut [u8], src: &[u8]) -> Result<(), Error>;

    /// Lets this crate recognise its own ciphers behind a `&dyn Block`, which
    /// is Go's `cipher.Block.(*aes.Block)` type assertion. Leave the default
    /// in implementations outside this crate.
    #[doc(hidden)]
    fn as_any(&self) -> Option<&dyn Any> {
        None
    }
}

/// Go's `cipher.Stream`: a stream cipher.
pub trait Stream {
    /// XORs each byte of `src` with the key stream into `dst`, which may be
    /// longer than `src`. Fails if `dst` is shorter.
    fn xor_key_stream(&mut self, dst: &mut [u8], src: &[u8]) -> Result<(), Error>;

    /// XORs `buf` with the key stream in place (Go's `dst` equal to `src`).
    fn xor_key_stream_in_place(&mut self, buf: &mut [u8]) {
        let src = buf.to_vec();
        self.xor_key_stream(buf, &src)
            .expect("equal-length buffers are always large enough");
    }
}

impl<S: Stream + ?Sized> Stream for Box<S> {
    fn xor_key_stream(&mut self, dst: &mut [u8], src: &[u8]) -> Result<(), Error> {
        (**self).xor_key_stream(dst, src)
    }

    fn xor_key_stream_in_place(&mut self, buf: &mut [u8]) {
        (**self).xor_key_stream_in_place(buf);
    }
}

/// Go's `cipher.BlockMode`: a block cipher in a mode that works on whole blocks.
pub trait BlockMode {
    /// Returns the mode's block size in bytes.
    fn block_size(&self) -> usize;

    /// Encrypts or decrypts the blocks of `src` into `dst`. `src` must be a
    /// whole number of blocks and `dst` at least as long. Successive calls
    /// chain, as in Go.
    fn crypt_blocks(&mut self, dst: &mut [u8], src: &[u8]) -> Result<(), Error>;

    /// Encrypts or decrypts `buf` in place (Go's `dst` equal to `src`).
    fn crypt_blocks_in_place(&mut self, buf: &mut [u8]) -> Result<(), Error>;
}

impl<M: BlockMode + ?Sized> BlockMode for Box<M> {
    fn block_size(&self) -> usize {
        (**self).block_size()
    }

    fn crypt_blocks(&mut self, dst: &mut [u8], src: &[u8]) -> Result<(), Error> {
        (**self).crypt_blocks(dst, src)
    }

    fn crypt_blocks_in_place(&mut self, buf: &mut [u8]) -> Result<(), Error> {
        (**self).crypt_blocks_in_place(buf)
    }
}

/// Go's `cipher.AEAD`: authenticated encryption with associated data.
pub trait Aead {
    /// Returns the nonce length `seal` and `open` require.
    fn nonce_size(&self) -> usize;

    /// Returns how many bytes a ciphertext is longer than its plaintext.
    fn overhead(&self) -> usize;

    /// Encrypts and authenticates `plaintext`, authenticates
    /// `additional_data` and appends the result to `dst`. Fails, appending
    /// nothing, on a wrong nonce length or an oversized message.
    fn seal(
        &self,
        dst: &mut Vec<u8>,
        nonce: &[u8],
        plaintext: &[u8],
        additional_data: &[u8],
    ) -> Result<(), Error>;

    /// Decrypts and authenticates `ciphertext`, authenticates
    /// `additional_data` and appends the plaintext to `dst`. On failure `dst`
    /// is left unchanged and no unauthenticated plaintext is released;
    /// [`Error::is_authentication_failure`] identifies a forged message.
    fn open(
        &self,
        dst: &mut Vec<u8>,
        nonce: &[u8],
        ciphertext: &[u8],
        additional_data: &[u8],
    ) -> Result<(), Error>;

    /// Replaces the plaintext in `buf` with its ciphertext (Go's
    /// `Seal(plaintext[:0], ...)`). `buf` is unchanged on error.
    fn seal_in_place(
        &self,
        buf: &mut Vec<u8>,
        nonce: &[u8],
        additional_data: &[u8],
    ) -> Result<(), Error> {
        let plaintext = std::mem::take(buf);
        let result = self.seal(buf, nonce, &plaintext, additional_data);
        if result.is_err() {
            *buf = plaintext;
        }
        result
    }

    /// Replaces the ciphertext in `buf` with its plaintext (Go's
    /// `Open(ciphertext[:0], ...)`). `buf` is unchanged on error.
    fn open_in_place(
        &self,
        buf: &mut Vec<u8>,
        nonce: &[u8],
        additional_data: &[u8],
    ) -> Result<(), Error> {
        let ciphertext = std::mem::take(buf);
        let result = self.open(buf, nonce, &ciphertext, additional_data);
        if result.is_err() {
            *buf = ciphertext;
        }
        result
    }
}

impl<A: Aead + ?Sized> Aead for Box<A> {
    fn nonce_size(&self) -> usize {
        (**self).nonce_size()
    }

    fn overhead(&self) -> usize {
        (**self).overhead()
    }

    fn seal(
        &self,
        dst: &mut Vec<u8>,
        nonce: &[u8],
        plaintext: &[u8],
        additional_data: &[u8],
    ) -> Result<(), Error> {
        (**self).seal(dst, nonce, plaintext, additional_data)
    }

    fn open(
        &self,
        dst: &mut Vec<u8>,
        nonce: &[u8],
        ciphertext: &[u8],
        additional_data: &[u8],
    ) -> Result<(), Error> {
        (**self).open(dst, nonce, ciphertext, additional_data)
    }
}

// ---------------------------------------------------------------------------
// Engines: the concrete RustCrypto ciphers the modes run over.

/// A [`Block`] seen through RustCrypto's cipher traits, for ciphers this crate
/// does not provide. Only 8- and 16-byte blocks are supported.
#[derive(Clone, Copy)]
pub(crate) struct Foreign<'a, N> {
    block: &'a dyn Block,
    size: PhantomData<N>,
}

impl<N: ArraySize> BlockSizeUser for Foreign<'_, N> {
    type BlockSize = N;
}

impl<N: ArraySize> ParBlocksSizeUser for Foreign<'_, N> {
    type ParBlocksSize = U1;
}

impl<N: ArraySize> BlockCipherEncBackend for Foreign<'_, N> {
    fn encrypt_block(&self, mut block: InOut<'_, '_, CipherBlock<Self>>) {
        let input = block.get_in().clone();
        self.block
            .encrypt(block.get_out().as_mut_slice(), input.as_slice())
            .expect("a Block must accept whole blocks");
    }
}

impl<N: ArraySize> BlockCipherDecBackend for Foreign<'_, N> {
    fn decrypt_block(&self, mut block: InOut<'_, '_, CipherBlock<Self>>) {
        let input = block.get_in().clone();
        self.block
            .decrypt(block.get_out().as_mut_slice(), input.as_slice())
            .expect("a Block must accept whole blocks");
    }
}

impl<N: ArraySize> BlockCipherEncrypt for Foreign<'_, N> {
    fn encrypt_with_backend(&self, f: impl BlockCipherEncClosure<BlockSize = N>) {
        f.call(self);
    }
}

impl<N: ArraySize> BlockCipherDecrypt for Foreign<'_, N> {
    fn decrypt_with_backend(&self, f: impl BlockCipherDecClosure<BlockSize = N>) {
        f.call(self);
    }
}

pub(crate) enum Engine<'a> {
    Aes128(::aes::Aes128),
    Aes192(::aes::Aes192),
    Aes256(::aes::Aes256),
    #[cfg(feature = "des")]
    Des(::des::Des),
    #[cfg(feature = "des")]
    TripleDes(::des::TdesEde3),
    Wide(Foreign<'a, U16>),
    Narrow(Foreign<'a, U8>),
}

impl<'a> Engine<'a> {
    fn new(block: &'a dyn Block) -> Result<Self, Error> {
        if let Some(any) = block.as_any() {
            if let Some(cipher) = any.downcast_ref::<crate::aes::Cipher>() {
                return Ok(cipher.engine());
            }
            #[cfg(feature = "des")]
            if let Some(cipher) = any.downcast_ref::<crate::des::Cipher>() {
                return Ok(Engine::Des(cipher.0.clone()));
            }
            #[cfg(feature = "des")]
            if let Some(cipher) = any.downcast_ref::<crate::des::TripleDesCipher>() {
                return Ok(Engine::TripleDes(cipher.0.clone()));
            }
        }
        match block.block_size() {
            16 => Ok(Engine::Wide(Foreign {
                block,
                size: PhantomData,
            })),
            8 => Ok(Engine::Narrow(Foreign {
                block,
                size: PhantomData,
            })),
            size => Err(Error::owned(format!(
                "crypto/cipher: block size {size} is not supported (only 8 and 16 bytes)"
            ))),
        }
    }

    /// Go type-asserts `*aes.Block` to pick fast paths, and a few messages
    /// differ between those and the generic implementations.
    fn is_aes(&self) -> bool {
        matches!(
            self,
            Engine::Aes128(_) | Engine::Aes192(_) | Engine::Aes256(_)
        )
    }
}

/// Evaluates `$body` once per engine type, binding the cipher to `$c`.
macro_rules! each_engine {
    ($engine:expr, $c:ident => $body:expr) => {
        match $engine {
            Engine::Aes128($c) => $body,
            Engine::Aes192($c) => $body,
            Engine::Aes256($c) => $body,
            #[cfg(feature = "des")]
            Engine::Des($c) => $body,
            #[cfg(feature = "des")]
            Engine::TripleDes($c) => $body,
            Engine::Wide($c) => $body,
            Engine::Narrow($c) => $body,
        }
    };
}

/// Like [`each_engine!`], with separate bodies for 16-byte and 8-byte blocks.
macro_rules! each_engine_by_width {
    ($engine:expr, wide $w:ident => $wide:expr, narrow $n:ident => $narrow:expr) => {
        match $engine {
            Engine::Aes128($w) => $wide,
            Engine::Aes192($w) => $wide,
            Engine::Aes256($w) => $wide,
            Engine::Wide($w) => $wide,
            #[cfg(feature = "des")]
            Engine::Des($n) => $narrow,
            #[cfg(feature = "des")]
            Engine::TripleDes($n) => $narrow,
            Engine::Narrow($n) => $narrow,
        }
    };
}

fn array_from<N: ArraySize>(slice: &[u8]) -> Array<u8, N> {
    Array::try_from(slice).expect("length checked by the caller")
}

// ---------------------------------------------------------------------------
// Block modes: CBC.

fn check_blocks(block_size: usize, dst: usize, src: usize) -> Result<(), Error> {
    if !src.is_multiple_of(block_size) {
        return Err(Error::new("crypto/cipher: input not full blocks"));
    }
    if dst < src {
        return Err(Error::new("crypto/cipher: output smaller than input"));
    }
    Ok(())
}

struct CbcEncrypter<C: BlockCipherEncrypt>(::cbc::Encryptor<C>);

impl<C: BlockCipherEncrypt> BlockMode for CbcEncrypter<C> {
    fn block_size(&self) -> usize {
        C::BlockSize::USIZE
    }

    fn crypt_blocks(&mut self, dst: &mut [u8], src: &[u8]) -> Result<(), Error> {
        check_blocks(C::BlockSize::USIZE, dst.len(), src.len())?;
        let buf = InOutBuf::new(src, &mut dst[..src.len()]).expect("lengths match");
        self.0
            .encrypt_blocks_inout(buf.into_chunks::<C::BlockSize>().0);
        Ok(())
    }

    fn crypt_blocks_in_place(&mut self, buf: &mut [u8]) -> Result<(), Error> {
        check_blocks(C::BlockSize::USIZE, buf.len(), buf.len())?;
        self.0
            .encrypt_blocks_inout(InOutBuf::from(buf).into_chunks::<C::BlockSize>().0);
        Ok(())
    }
}

struct CbcDecrypter<C: BlockCipherDecrypt>(::cbc::Decryptor<C>);

impl<C: BlockCipherDecrypt> BlockMode for CbcDecrypter<C> {
    fn block_size(&self) -> usize {
        C::BlockSize::USIZE
    }

    fn crypt_blocks(&mut self, dst: &mut [u8], src: &[u8]) -> Result<(), Error> {
        check_blocks(C::BlockSize::USIZE, dst.len(), src.len())?;
        let buf = InOutBuf::new(src, &mut dst[..src.len()]).expect("lengths match");
        self.0
            .decrypt_blocks_inout(buf.into_chunks::<C::BlockSize>().0);
        Ok(())
    }

    fn crypt_blocks_in_place(&mut self, buf: &mut [u8]) -> Result<(), Error> {
        check_blocks(C::BlockSize::USIZE, buf.len(), buf.len())?;
        self.0
            .decrypt_blocks_inout(InOutBuf::from(buf).into_chunks::<C::BlockSize>().0);
        Ok(())
    }
}

fn make_cbc_encrypter<'a, C>(cipher: C, iv: &[u8]) -> Box<dyn BlockMode + 'a>
where
    C: BlockCipherEncrypt + 'a,
{
    let iv = array_from(iv);
    Box::new(CbcEncrypter(::cbc::Encryptor::<C>::inner_iv_init(
        cipher, &iv,
    )))
}

fn make_cbc_decrypter<'a, C>(cipher: C, iv: &[u8]) -> Box<dyn BlockMode + 'a>
where
    C: BlockCipherDecrypt + 'a,
{
    let iv = array_from(iv);
    Box::new(CbcDecrypter(::cbc::Decryptor::<C>::inner_iv_init(
        cipher, &iv,
    )))
}

/// Returns a [`BlockMode`] that encrypts in cipher block chaining mode,
/// like `cipher.NewCBCEncrypter`. The length of `iv` must equal the block size.
pub fn cbc_encrypter<'a>(
    block: &'a dyn Block,
    iv: &[u8],
) -> Result<Box<dyn BlockMode + 'a>, Error> {
    if iv.len() != block.block_size() {
        return Err(Error::new(
            "cipher.NewCBCEncrypter: IV length must equal block size",
        ));
    }
    Ok(each_engine!(Engine::new(block)?, c => make_cbc_encrypter(c, iv)))
}

/// Returns a [`BlockMode`] that decrypts in cipher block chaining mode,
/// like `cipher.NewCBCDecrypter`. The length of `iv` must equal the block size.
pub fn cbc_decrypter<'a>(
    block: &'a dyn Block,
    iv: &[u8],
) -> Result<Box<dyn BlockMode + 'a>, Error> {
    if iv.len() != block.block_size() {
        return Err(Error::new(
            "cipher.NewCBCDecrypter: IV length must equal block size",
        ));
    }
    Ok(each_engine!(Engine::new(block)?, c => make_cbc_decrypter(c, iv)))
}

// ---------------------------------------------------------------------------
// Stream modes: CFB, CTR, OFB.

/// A keystream operation that works on one buffer.
trait Apply {
    fn apply(&mut self, buf: &mut [u8]);
}

struct Keystream<S>(S);

impl<S: StreamCipher> Apply for Keystream<S> {
    fn apply(&mut self, buf: &mut [u8]) {
        self.0.apply_keystream(buf);
    }
}

struct CfbEncrypter<C: BlockCipherEncrypt>(::cfb_mode::BufEncryptor<C>);

impl<C: BlockCipherEncrypt> Apply for CfbEncrypter<C> {
    fn apply(&mut self, buf: &mut [u8]) {
        self.0.encrypt(buf);
    }
}

struct CfbDecrypter<C: BlockCipherEncrypt>(::cfb_mode::BufDecryptor<C>);

impl<C: BlockCipherEncrypt> Apply for CfbDecrypter<C> {
    fn apply(&mut self, buf: &mut [u8]) {
        self.0.decrypt(buf);
    }
}

/// Adapts an [`Apply`] to [`Stream`] with Go's short-output message.
struct Filter<T> {
    inner: T,
    short_output: &'static str,
}

impl<T: Apply> Stream for Filter<T> {
    fn xor_key_stream(&mut self, dst: &mut [u8], src: &[u8]) -> Result<(), Error> {
        if dst.len() < src.len() {
            return Err(Error::new(self.short_output));
        }
        let dst = &mut dst[..src.len()];
        dst.copy_from_slice(src);
        self.inner.apply(dst);
        Ok(())
    }

    fn xor_key_stream_in_place(&mut self, buf: &mut [u8]) {
        self.inner.apply(buf);
    }
}

const SHORT_OUTPUT: &str = "crypto/cipher: output smaller than input";

fn stream<'a, T: Apply + 'a>(inner: T, short_output: &'static str) -> Box<dyn Stream + 'a> {
    Box::new(Filter {
        inner,
        short_output,
    })
}

fn cfb<'a, C>(cipher: C, iv: &[u8], decrypt: bool) -> Box<dyn Stream + 'a>
where
    C: BlockCipherEncrypt + 'a,
{
    let iv = array_from(iv);
    if decrypt {
        stream(
            CfbDecrypter(::cfb_mode::BufDecryptor::<C>::inner_iv_init(cipher, &iv)),
            SHORT_OUTPUT,
        )
    } else {
        stream(
            CfbEncrypter(::cfb_mode::BufEncryptor::<C>::inner_iv_init(cipher, &iv)),
            SHORT_OUTPUT,
        )
    }
}

fn new_cfb<'a>(
    block: &'a dyn Block,
    iv: &[u8],
    decrypt: bool,
) -> Result<Box<dyn Stream + 'a>, Error> {
    if iv.len() != block.block_size() {
        return Err(Error::new("cipher.newCFB: IV length must equal block size"));
    }
    Ok(each_engine!(Engine::new(block)?, c => cfb(c, iv, decrypt)))
}

/// Returns a [`Stream`] that encrypts with cipher feedback mode, like
/// `cipher.NewCFBEncrypter`. The length of `iv` must equal the block size.
///
/// Deprecated in Go, and here, for the same reason: CFB is not authenticated.
/// Use an [`Aead`] mode.
pub fn cfb_encrypter<'a>(block: &'a dyn Block, iv: &[u8]) -> Result<Box<dyn Stream + 'a>, Error> {
    new_cfb(block, iv, false)
}

/// Returns a [`Stream`] that decrypts with cipher feedback mode, like
/// `cipher.NewCFBDecrypter`. The length of `iv` must equal the block size.
///
/// Deprecated in Go, and here, for the same reason: CFB is not authenticated.
/// Use an [`Aead`] mode.
pub fn cfb_decrypter<'a>(block: &'a dyn Block, iv: &[u8]) -> Result<Box<dyn Stream + 'a>, Error> {
    new_cfb(block, iv, true)
}

/// The counter is the whole block, big-endian, incremented modulo 2^128 (16
/// byte blocks) or 2^64 (8 byte blocks), exactly as Go does.
fn ctr_wide<'a, C>(cipher: C, iv: &[u8], short_output: &'static str) -> Box<dyn Stream + 'a>
where
    C: BlockCipherEncrypt<BlockSize = U16> + 'a,
{
    let iv = array_from(iv);
    stream(
        Keystream(StreamCipherCoreWrapper::from_core(::ctr::CtrCore::<
            C,
            ::ctr::flavors::Ctr128BE,
        >::inner_iv_init(
            cipher, &iv
        ))),
        short_output,
    )
}

fn ctr_narrow<'a, C>(cipher: C, iv: &[u8], short_output: &'static str) -> Box<dyn Stream + 'a>
where
    C: BlockCipherEncrypt<BlockSize = U8> + 'a,
{
    let iv = array_from(iv);
    stream(
        Keystream(StreamCipherCoreWrapper::from_core(::ctr::CtrCore::<
            C,
            ::ctr::flavors::Ctr64BE,
        >::inner_iv_init(
            cipher, &iv
        ))),
        short_output,
    )
}

/// Returns a [`Stream`] that encrypts or decrypts with counter mode, like
/// `cipher.NewCTR`. The length of `iv` must equal the block size.
pub fn ctr<'a>(block: &'a dyn Block, iv: &[u8]) -> Result<Box<dyn Stream + 'a>, Error> {
    let engine = Engine::new(block)?;
    // Go routes *aes.Block to crypto/aes' own CTR, with its own messages.
    let (bad_iv, short_output) = if engine.is_aes() {
        ("bad IV length", "crypto/aes: len(dst) < len(src)")
    } else {
        (
            "cipher.NewCTR: IV length must equal block size",
            SHORT_OUTPUT,
        )
    };
    if iv.len() != block.block_size() {
        return Err(Error::new(bad_iv));
    }
    Ok(each_engine_by_width!(
        engine,
        wide c => ctr_wide(c, iv, short_output),
        narrow c => ctr_narrow(c, iv, short_output)
    ))
}

fn ofb_wide<'a, C>(cipher: C, iv: &[u8]) -> Box<dyn Stream + 'a>
where
    C: BlockCipherEncrypt<BlockSize = U16> + 'a,
{
    let iv = array_from(iv);
    stream(
        Keystream(StreamCipherCoreWrapper::from_core(
            ::ofb::OfbCore::<C>::inner_iv_init(cipher, &iv),
        )),
        SHORT_OUTPUT,
    )
}

fn ofb_narrow<'a, C>(cipher: C, iv: &[u8]) -> Box<dyn Stream + 'a>
where
    C: BlockCipherEncrypt<BlockSize = U8> + 'a,
{
    let iv = array_from(iv);
    stream(
        Keystream(StreamCipherCoreWrapper::from_core(
            ::ofb::OfbCore::<C>::inner_iv_init(cipher, &iv),
        )),
        SHORT_OUTPUT,
    )
}

/// Returns a [`Stream`] that encrypts or decrypts with output feedback mode,
/// like `cipher.NewOFB`. The length of `iv` must equal the block size.
///
/// Deprecated in Go, and here, for the same reason: OFB is not authenticated.
/// Use [`fn@ctr`] or an [`Aead`] mode.
pub fn ofb<'a>(block: &'a dyn Block, iv: &[u8]) -> Result<Box<dyn Stream + 'a>, Error> {
    if iv.len() != block.block_size() {
        return Err(Error::new("cipher.NewOFB: IV length must equal block size"));
    }
    Ok(each_engine_by_width!(
        Engine::new(block)?,
        wide c => ofb_wide(c, iv),
        narrow c => ofb_narrow(c, iv)
    ))
}

// ---------------------------------------------------------------------------
// Galois/Counter Mode.

/// Any 128-bit block cipher, as one type so that the GCM constructors
/// instantiate `aes-gcm` once per nonce and tag size rather than per cipher.
enum Block128<'a> {
    Aes128(::aes::Aes128),
    Aes192(::aes::Aes192),
    Aes256(::aes::Aes256),
    Foreign(Foreign<'a, U16>),
}

impl BlockSizeUser for Block128<'_> {
    type BlockSize = U16;
}

impl BlockCipherEncrypt for Block128<'_> {
    fn encrypt_with_backend(&self, f: impl BlockCipherEncClosure<BlockSize = U16>) {
        match self {
            Block128::Aes128(c) => c.encrypt_with_backend(f),
            Block128::Aes192(c) => c.encrypt_with_backend(f),
            Block128::Aes256(c) => c.encrypt_with_backend(f),
            Block128::Foreign(c) => c.encrypt_with_backend(f),
        }
    }
}

/// One `aes-gcm` instantiation, with the nonce and tag sizes erased.
trait GcmCore {
    fn seal(&self, nonce: &[u8], additional_data: &[u8], buf: &mut [u8]) -> Vec<u8>;
    fn open(&self, nonce: &[u8], additional_data: &[u8], buf: &mut [u8], tag: &[u8]) -> bool;
}

/// `aes-gcm` is generic over the nonce and tag sizes; `Core` carries them.
struct Core<'a, N, T: ::aes_gcm::TagSize>(AesGcm<Block128<'a>, N, T>);

impl<N: ArraySize, T: ::aes_gcm::TagSize> GcmCore for Core<'_, N, T> {
    fn seal(&self, nonce: &[u8], additional_data: &[u8], buf: &mut [u8]) -> Vec<u8> {
        let nonce = array_from::<N>(nonce);
        let tag = self
            .0
            .encrypt_inout_detached(&nonce, additional_data, InOutBuf::from(buf))
            .expect("message size checked by the caller");
        tag.to_vec()
    }

    fn open(&self, nonce: &[u8], additional_data: &[u8], buf: &mut [u8], tag: &[u8]) -> bool {
        let nonce = array_from::<N>(nonce);
        let tag = array_from::<T>(tag);
        self.0
            .decrypt_inout_detached(&nonce, additional_data, InOutBuf::from(buf), &tag)
            .is_ok()
    }
}

/// The nonce sizes, in bytes, `gcm_with_nonce_size` accepts: Go takes any
/// positive size, but the `aes-gcm` crate needs each one at compile time.
pub const GCM_NONCE_SIZES: [usize; 48] = [
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
    27, 28, 29, 30, 31, 32, 36, 40, 44, 48, 56, 60, 64, 72, 80, 96, 100, 112, 120, 128, 192, 256,
];

/// Builds the `aes-gcm` instance for one tag size over every supported nonce
/// size; the list matches [`GCM_NONCE_SIZES`].
macro_rules! gcm_for_nonce {
    ($cipher:expr, $nonce:expr, $tag:ty) => {
        gcm_for_nonce!(@list $cipher, $nonce, $tag,
            U1 U2 U3 U4 U5 U6 U7 U8 U9 U10 U11 U12 U13 U14 U15 U16 U17 U18 U19 U20 U21 U22 U23 U24 U25 U26 U27 U28 U29 U30 U31 U32 U36 U40 U44 U48 U56 U60 U64 U72 U80 U96 U100 U112 U120 U128 U192 U256)
    };
    (@list $cipher:expr, $nonce:expr, $tag:ty, $($size:ident)*) => {{
        use ::aes::cipher::consts::*;
        match $nonce {
            $(n if n == <$size as Unsigned>::USIZE => {
                Some(Box::new(Core::<$size, $tag>(AesGcm::from($cipher))) as Box<dyn GcmCore + '_>)
            })*
            _ => None,
        }
    }};
}

fn gcm_instance<'a>(
    cipher: Block128<'a>,
    nonce_size: usize,
    tag_size: usize,
) -> Option<Box<dyn GcmCore + 'a>> {
    match tag_size {
        12 => gcm_for_nonce!(cipher, nonce_size, U12),
        13 => gcm_for_nonce!(cipher, nonce_size, U13),
        14 => gcm_for_nonce!(cipher, nonce_size, U14),
        15 => gcm_for_nonce!(cipher, nonce_size, U15),
        _ => gcm_for_nonce!(cipher, nonce_size, U16),
    }
}

struct GcmAead<'a> {
    core: Box<dyn GcmCore + 'a>,
    nonce_size: usize,
    tag_size: usize,
}

/// Go's bound on a GCM message: (2^32 - 2) blocks of 16 bytes.
const MAX_MESSAGE: u64 = ((1 << 32) - 2) * 16;

impl Aead for GcmAead<'_> {
    fn nonce_size(&self) -> usize {
        self.nonce_size
    }

    fn overhead(&self) -> usize {
        self.tag_size
    }

    fn seal(
        &self,
        dst: &mut Vec<u8>,
        nonce: &[u8],
        plaintext: &[u8],
        additional_data: &[u8],
    ) -> Result<(), Error> {
        if nonce.len() != self.nonce_size {
            return Err(Error::new(
                "crypto/cipher: incorrect nonce length given to GCM",
            ));
        }
        if plaintext.len() as u64 > MAX_MESSAGE {
            return Err(Error::new("crypto/cipher: message too large for GCM"));
        }
        let start = dst.len();
        dst.extend_from_slice(plaintext);
        let tag = self.core.seal(nonce, additional_data, &mut dst[start..]);
        dst.extend_from_slice(&tag[..self.tag_size]);
        Ok(())
    }

    fn open(
        &self,
        dst: &mut Vec<u8>,
        nonce: &[u8],
        ciphertext: &[u8],
        additional_data: &[u8],
    ) -> Result<(), Error> {
        if nonce.len() != self.nonce_size {
            return Err(Error::new(
                "crypto/cipher: incorrect nonce length given to GCM",
            ));
        }
        if ciphertext.len() < self.tag_size {
            return Err(ERR_OPEN);
        }
        if ciphertext.len() as u64 > MAX_MESSAGE + self.tag_size as u64 {
            return Err(ERR_OPEN);
        }
        let (body, tag) = ciphertext.split_at(ciphertext.len() - self.tag_size);
        // Decrypt a copy so that dst never holds unauthenticated plaintext.
        let mut plaintext = body.to_vec();
        if !self.core.open(nonce, additional_data, &mut plaintext, tag) {
            return Err(ERR_OPEN);
        }
        dst.extend_from_slice(&plaintext);
        Ok(())
    }
}

/// Go's `gcmWithRandomNonce`: a fresh 96-bit nonce is prepended by `seal` and
/// consumed by `open`.
struct GcmRandomNonce<'a>(GcmAead<'a>);

const RANDOM_NONCE_SIZE: usize = 12;
const STANDARD_TAG_SIZE: usize = 16;

impl Aead for GcmRandomNonce<'_> {
    fn nonce_size(&self) -> usize {
        0
    }

    fn overhead(&self) -> usize {
        RANDOM_NONCE_SIZE + STANDARD_TAG_SIZE
    }

    fn seal(
        &self,
        dst: &mut Vec<u8>,
        nonce: &[u8],
        plaintext: &[u8],
        additional_data: &[u8],
    ) -> Result<(), Error> {
        if !nonce.is_empty() {
            return Err(Error::new(
                "crypto/cipher: non-empty nonce passed to GCMWithRandomNonce",
            ));
        }
        let mut random = [0u8; RANDOM_NONCE_SIZE];
        crate::rand::read(&mut random);
        let start = dst.len();
        dst.extend_from_slice(&random);
        let result = self.0.seal(dst, &random, plaintext, additional_data);
        if result.is_err() {
            dst.truncate(start);
        }
        result
    }

    fn open(
        &self,
        dst: &mut Vec<u8>,
        nonce: &[u8],
        ciphertext: &[u8],
        additional_data: &[u8],
    ) -> Result<(), Error> {
        if !nonce.is_empty() {
            return Err(Error::new(
                "crypto/cipher: non-empty nonce passed to GCMWithRandomNonce",
            ));
        }
        if ciphertext.len() < RANDOM_NONCE_SIZE + STANDARD_TAG_SIZE {
            return Err(ERR_OPEN);
        }
        let (random, rest) = ciphertext.split_at(RANDOM_NONCE_SIZE);
        self.0.open(dst, random, rest, additional_data)
    }
}

const GCM_BLOCK_SIZE: usize = 16;
const GCM_STANDARD_NONCE_SIZE: usize = 12;
const GCM_MINIMUM_TAG_SIZE: usize = 12;

fn new_gcm_sized<'a>(
    block: &'a dyn Block,
    nonce_size: usize,
    tag_size: usize,
) -> Result<GcmAead<'a>, Error> {
    // The order of Go's checks: tag size, nonce size, then block size.
    if !(GCM_MINIMUM_TAG_SIZE..=GCM_BLOCK_SIZE).contains(&tag_size) {
        return Err(Error::new("cipher: incorrect tag size given to GCM"));
    }
    if nonce_size == 0 {
        return Err(Error::new("cipher: the nonce can't have zero length"));
    }
    let cipher = match Engine::new(block)? {
        Engine::Aes128(c) => Block128::Aes128(c),
        Engine::Aes192(c) => Block128::Aes192(c),
        Engine::Aes256(c) => Block128::Aes256(c),
        Engine::Wide(c) => Block128::Foreign(c),
        #[cfg(feature = "des")]
        Engine::Des(_) | Engine::TripleDes(_) => {
            return Err(Error::new("cipher: NewGCM requires 128-bit block cipher"));
        }
        Engine::Narrow(_) => {
            return Err(Error::new("cipher: NewGCM requires 128-bit block cipher"));
        }
    };
    let Some(core) = gcm_instance(cipher, nonce_size, tag_size) else {
        return Err(Error::owned(format!(
            "crypto/cipher: GCM nonce size {nonce_size} is not supported (see GCM_NONCE_SIZES)"
        )));
    };
    Ok(GcmAead {
        core,
        nonce_size,
        tag_size,
    })
}

/// Returns the 128-bit `block` wrapped in Galois Counter Mode with the
/// standard 12-byte nonce and 16-byte tag, like `cipher.NewGCM`.
pub fn gcm<'a>(block: &'a dyn Block) -> Result<Box<dyn Aead + 'a>, Error> {
    Ok(Box::new(new_gcm_sized(
        block,
        GCM_STANDARD_NONCE_SIZE,
        STANDARD_TAG_SIZE,
    )?))
}

/// Like [`gcm`], accepting nonces of `size` bytes, like
/// `cipher.NewGCMWithNonceSize`. The size must be positive and one of
/// [`GCM_NONCE_SIZES`].
pub fn gcm_with_nonce_size<'a>(
    block: &'a dyn Block,
    size: usize,
) -> Result<Box<dyn Aead + 'a>, Error> {
    Ok(Box::new(new_gcm_sized(block, size, STANDARD_TAG_SIZE)?))
}

/// Like [`gcm`], generating tags of `tag_size` bytes (12 to 16), like
/// `cipher.NewGCMWithTagSize`.
pub fn gcm_with_tag_size<'a>(
    block: &'a dyn Block,
    tag_size: usize,
) -> Result<Box<dyn Aead + 'a>, Error> {
    Ok(Box::new(new_gcm_sized(
        block,
        GCM_STANDARD_NONCE_SIZE,
        tag_size,
    )?))
}

/// Wraps an AES `block` in Galois Counter Mode with random 96-bit nonces
/// prepended to each ciphertext, like `cipher.NewGCMWithRandomNonce`. The
/// returned AEAD has a nonce size of zero and an overhead of 28 bytes. The
/// block must come from [`crate::aes::Cipher::new`].
pub fn gcm_with_random_nonce<'a>(block: &'a dyn Block) -> Result<Box<dyn Aead + 'a>, Error> {
    let is_aes = block
        .as_any()
        .is_some_and(|any| any.is::<crate::aes::Cipher>());
    if !is_aes {
        return Err(Error::new(
            "cipher: NewGCMWithRandomNonce requires aes.Block",
        ));
    }
    Ok(Box::new(GcmRandomNonce(new_gcm_sized(
        block,
        GCM_STANDARD_NONCE_SIZE,
        STANDARD_TAG_SIZE,
    )?)))
}

// ---------------------------------------------------------------------------
// Streams over io.

/// Go's `cipher.StreamReader`: wraps a reader, XORing what it reads with a
/// [`Stream`].
#[derive(Debug)]
pub struct StreamReader<S, R> {
    /// The key stream.
    pub s: S,
    /// The wrapped reader.
    pub r: R,
}

impl<S: Stream, R: io::Read> io::Read for StreamReader<S, R> {
    fn read(&mut self, dst: &mut [u8]) -> io::Result<usize> {
        let n = self.r.read(dst)?;
        self.s.xor_key_stream_in_place(&mut dst[..n]);
        Ok(n)
    }
}

/// Go's `cipher.StreamWriter`: wraps a writer, XORing what is written with a
/// [`Stream`].
#[derive(Debug)]
pub struct StreamWriter<S, W> {
    /// The key stream.
    pub s: S,
    /// The wrapped writer.
    pub w: W,
    /// Unused, as in Go.
    pub err: Option<io::Error>,
}

impl<S, W> StreamWriter<S, W> {
    /// Returns a writer for `w` that encrypts with `s`.
    pub fn new(s: S, w: W) -> Self {
        StreamWriter { s, w, err: None }
    }
}

impl<S: Stream, W: io::Write> io::Write for StreamWriter<S, W> {
    /// XORs `src` with the key stream and writes it. As in Go, a short write
    /// is an error, because the key stream has already advanced past `src`.
    fn write(&mut self, src: &[u8]) -> io::Result<usize> {
        let mut encrypted = vec![0; src.len()];
        self.s
            .xor_key_stream(&mut encrypted, src)
            .map_err(io::Error::other)?;
        let n = self.w.write(&encrypted)?;
        if n != src.len() {
            return Err(io::Error::new(io::ErrorKind::WriteZero, "short write"));
        }
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.w.flush()
    }
}

impl<S, W: io::Write> StreamWriter<S, W> {
    /// Finishes the writer, like `StreamWriter.Close`.
    ///
    /// Rust has no `io.Closer`: a writer is closed by dropping it, so this
    /// flushes the underlying writer, drops it and returns the flush result.
    pub fn close(mut self) -> io::Result<()> {
        self.w.flush()
    }
}
