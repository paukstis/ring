// Copyright 2015-2016 Brian Smith.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND AND THE AUTHORS DISCLAIM ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

use {der, digest, error, polyfill};
use untrusted;

#[cfg(feature = "rsa_signing")]
use rand;

#[cfg(feature = "rsa_signing")]
pub trait Encoding : Sync {
    fn encode(&self, msg: &[u8], out: &mut [u8], rng: &rand::SecureRandom)
              -> Result<(), error::Unspecified>;
}

/// The term "Verification" comes from RFC 3447.
pub trait Verification : Sync {
    fn verify(&self, msg: untrusted::Input, encoded: untrusted::Input)
              -> Result<(), error::Unspecified>;
}

pub struct PKCS1 {
    digest_alg: &'static digest::Algorithm,
    digestinfo_prefix: &'static [u8],
}

#[cfg(feature ="rsa_signing")]
impl Encoding for PKCS1 {
    // Implement padding procedure per EMSA-PKCS1-v1_5,
    // https://tools.ietf.org/html/rfc3447#section-9.2.
    fn encode(&self, msg: &[u8], out: &mut [u8], _: &rand::SecureRandom)
              -> Result<(), error::Unspecified> {
        let digest_len =
            self.digestinfo_prefix.len() + self.digest_alg.output_len;

        // Require at least 8 bytes of padding. Since we disallow keys smaller
        // than 2048 bits, this should never happen anyway.
        debug_assert!(out.len() >= digest_len + 11);
        let pad_len = out.len() - digest_len - 3;
        out[0] = 0;
        out[1] = 1;
        for i in 0..pad_len {
            out[2 + i] = 0xff;
        }
        out[2 + pad_len] = 0;

        let (digest_prefix, digest_dst) = out[3 + pad_len..].split_at_mut(
            self.digestinfo_prefix.len());
        digest_prefix.copy_from_slice(self.digestinfo_prefix);
        digest_dst.copy_from_slice(
            digest::digest(self.digest_alg, msg).as_ref());
        Ok(())
    }
}

macro_rules! rsa_pkcs1_padding {
    ( $PADDING_ALGORITHM:ident, $digest_alg:expr, $digestinfo_prefix:expr,
      $doc_str:expr ) => {
        #[doc=$doc_str]
        /// Feature: `rsa_signing`.
        pub static $PADDING_ALGORITHM: PKCS1 = PKCS1 {
            digest_alg: $digest_alg,
            digestinfo_prefix: $digestinfo_prefix,
        };
    }
}

rsa_pkcs1_padding!(RSA_PKCS1_SHA1, &digest::SHA1,
                   &SHA1_PKCS1_DIGESTINFO_PREFIX,
                   "PKCS#1 1.5 padding using SHA-1 for RSA signatures.");
rsa_pkcs1_padding!(RSA_PKCS1_SHA256, &digest::SHA256,
                   &SHA256_PKCS1_DIGESTINFO_PREFIX,
                   "PKCS#1 1.5 padding using SHA-256 for RSA signatures.");
rsa_pkcs1_padding!(RSA_PKCS1_SHA384, &digest::SHA384,
                   &SHA384_PKCS1_DIGESTINFO_PREFIX,
                   "PKCS#1 1.5 padding using SHA-384 for RSA signatures.");
rsa_pkcs1_padding!(RSA_PKCS1_SHA512, &digest::SHA512,
                   &SHA512_PKCS1_DIGESTINFO_PREFIX,
                   "PKCS#1 1.5 padding using SHA-512 for RSA signatures.");

macro_rules! pkcs1_digestinfo_prefix {
    ( $name:ident, $digest_len:expr, $digest_oid_len:expr,
      [ $( $digest_oid:expr ),* ] ) => {
        static $name: [u8; 2 + 8 + $digest_oid_len] = [
            der::Tag::Sequence as u8, 8 + $digest_oid_len + $digest_len,
                der::Tag::Sequence as u8, 2 + $digest_oid_len + 2,
                    der::Tag::OID as u8, $digest_oid_len, $( $digest_oid ),*,
                    der::Tag::Null as u8, 0,
                der::Tag::OctetString as u8, $digest_len,
        ];
    }
}

pkcs1_digestinfo_prefix!(
    SHA1_PKCS1_DIGESTINFO_PREFIX, 20, 5, [ 0x2b, 0x0e, 0x03, 0x02, 0x1a ]);

pkcs1_digestinfo_prefix!(
    SHA256_PKCS1_DIGESTINFO_PREFIX, 32, 9,
    [ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01 ]);

pkcs1_digestinfo_prefix!(
    SHA384_PKCS1_DIGESTINFO_PREFIX, 48, 9,
    [ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02 ]);

pkcs1_digestinfo_prefix!(
    SHA512_PKCS1_DIGESTINFO_PREFIX, 64, 9,
    [ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03 ]);

impl Verification for PKCS1 {
    fn verify(&self, msg: untrusted::Input, encoded: untrusted::Input)
              -> Result<(), error::Unspecified> {
        encoded.read_all(error::Unspecified, |decoded| {
            if try!(decoded.read_byte()) != 0 ||
               try!(decoded.read_byte()) != 1 {
                return Err(error::Unspecified);
            }

            let mut ps_len = 0;
            loop {
                match try!(decoded.read_byte()) {
                    0xff => { ps_len += 1; },
                    0x00 => { break; },
                    _ => { return Err(error::Unspecified); }
                }
            }
            if ps_len < 8 {
                return Err(error::Unspecified);
            }

            let decoded_digestinfo_prefix =
                try!(decoded.skip_and_get_input(
                        self.digestinfo_prefix.len()));
            if decoded_digestinfo_prefix != self.digestinfo_prefix {
                return Err(error::Unspecified);
            }

            let digest_alg = self.digest_alg;
            let decoded_digest =
                try!(decoded.skip_and_get_input(digest_alg.output_len));
            let digest = digest::digest(digest_alg, msg.as_slice_less_safe());
            if decoded_digest != digest.as_ref() {
                return Err(error::Unspecified);
            }
            Ok(())
        })
    }
}

/// PSS Padding as described in https://tools.ietf.org/html/rfc3447#section-9.1.
/// Salt length is fixed to be the length of the output of the digest algorithm.
/// The only mask generating function supported is MGF1.
/// The size (in bits) of the RSA moduli is assumed to be a multiple of 8.
pub struct PSS {
    pub digest_alg: &'static digest::Algorithm,
}

// Maxmimum supported output length for PSS padding.
const MAX_OUTPUT_LEN: usize = 4096;

impl Verification for PSS {
    // PSS verification as specified in
    // https://tools.ietf.org/html/rfc3447#section-9.1.2
    fn verify(&self, msg: untrusted::Input, encoded: untrusted::Input)
              -> Result<(), error::Unspecified> {

        let em_len = encoded.len();
        encoded.read_all(error::Unspecified, |em| {
            let digest_len = self.digest_alg.output_len;

            // Step 2.
            let m_hash = digest::digest(self.digest_alg,
                                        msg.as_slice_less_safe());

            // Step 3: where we assume the digest and salt are of equal length.
            if em_len < 2 + (2 * digest_len) {
                return Err(error::Unspecified)
            }

            // Steps 4 and 5: Parse encoded message as:
            //     masked_db || h_hash || 0xbc
            let db_len = em_len - digest_len - 1;
            let masked_db = try!(em.skip_and_get_input(db_len));
            let h_hash = try!(em.skip_and_get_input(digest_len));
            if try!(em.read_byte()) != 0xbc {
                return Err(error::Unspecified);
            }

            // Step 7.
            let mut db = [0u8; MAX_OUTPUT_LEN];
            try!(mgf1(h_hash.as_slice_less_safe(), db_len, &mut db,
                      self.digest_alg));

            try!(masked_db.read_all(error::Unspecified, |masked_bytes| {
                // Step 6. Moduli lengths are always a multiple of 8 so the top
                // bit must be 0.
                let b = try!(masked_bytes.read_byte());
                if b & 0x80 != 0 {
                    return Err(error::Unspecified);
                } else {
                    db[0] ^= b;
                }

                // Step 8.
                for i in 1..db_len {
                    let b = try!(masked_bytes.read_byte());
                    db[i] ^= b;
                }
                Ok(())
            }));

            // Step 9.
            db[0] &= 0x7f;

            // Step 10.
            let pad_len = db_len - digest_len - 1;
            for i in 0..pad_len {
                if db[i] != 0 {
                    return Err(error::Unspecified);
                }
            }
            if db[pad_len] != 1 {
                return Err(error::Unspecified);
            }

            // Step 11.
            let salt = &db[db_len - digest_len..][..digest_len];

            // Step 12 and 13: compute hash value of:
            //     (0x)00 00 00 00 00 00 00 00 || m_hash || salt
            let mut ctx = digest::Context::new(self.digest_alg);
            let prefix = [0u8; 8];
            ctx.update(&prefix);
            ctx.update(m_hash.as_ref());
            ctx.update(&salt);
            let h_hash_check = ctx.finish();

            // Step 14.
            if h_hash != h_hash_check.as_ref() {
                return Err(error::Unspecified);
            }

            Ok(())
        })
    }
}

// Mask-generating function MGF1 as described in
// https://tools.ietf.org/html/rfc3447#appendix-B.2.1.
fn mgf1(seed: &[u8], mask_len: usize, mask: &mut [u8],
        digest_alg: &'static digest::Algorithm)
        -> Result<(), error::Unspecified> {

    let digest_len = digest_alg.output_len;

    // Maximum counter value is the value of (mask_len / digest_len) rounded up.
    let ctr_max = 1 + ((mask_len - 1) / digest_len);
    for i in 0..ctr_max {
        let mut ctx = digest::Context::new(digest_alg);
        ctx.update(seed);
        ctx.update(&polyfill::slice::be_u8_from_u32(i as u32));
        let digest = ctx.finish();
        mask[i * digest_len..][..digest_len].copy_from_slice(digest.as_ref());
    }

    Ok(())
}

macro_rules! rsa_pss_padding {
    ( $PADDING_ALGORITHM:ident, $digest_alg:expr, $doc_str:expr ) => {
        #[doc=$doc_str]
        /// Feature: `rsa_signing`.
        pub static $PADDING_ALGORITHM: PSS = PSS {
            digest_alg: $digest_alg,
        };
    }
}

rsa_pss_padding!(RSA_PSS_SHA256, &digest::SHA256,
                 "PSS padding using SHA-256 for RSA signatures.");
rsa_pss_padding!(RSA_PSS_SHA384, &digest::SHA384,
                 "PSS padding using SHA-384 for RSA signatures.");
rsa_pss_padding!(RSA_PSS_SHA512, &digest::SHA512,
                 "PSS padding using SHA-512 for RSA signatures.");
