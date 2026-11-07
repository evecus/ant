//! Minimal HPKE (RFC 9180) base-mode provider for rustls ECH (client side).
//!
//! rustls 0.23.28+ implements client-side ECH (RFC 9849) but requires the
//! caller to supply an [`rustls::crypto::hpke::Hpke`] provider. The `ring`
//! provider does not ship one — only `aws-lc-rs` does, and that pulls in a C
//! toolchain ant cannot afford on aarch64-musl / mipsel cross builds.
//!
//! This module implements exactly what ECH needs, on the same pure-Rust
//! RustCrypto crates the REALITY module already uses:
//!
//! * KEM:  DHKEM(X25519, HKDF-SHA256) — `0x0020`, the only KEM ECH servers
//!   in the wild publish (Cloudflare et al).
//! * KDF:  HKDF-SHA256 — `0x0001`.
//! * AEAD: AES-128-GCM `0x0001` / AES-256-GCM `0x0002` / ChaCha20-Poly1305
//!   `0x0003`.
//!
//! Only base mode (`mode_base = 0x00`) is implemented — ECH never uses the
//! PSK / auth modes. Correctness is pinned by the RFC 9180 Appendix A.1
//! official test vectors (see `tests` below).

use aes_gcm::aead::AeadInPlace;
use aes_gcm::{Aes128Gcm, Aes256Gcm, KeyInit};
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret as XStaticSecret};

use rustls::crypto::hpke::{
    EncapsulatedSecret, Hpke, HpkeOpener, HpkePrivateKey, HpkePublicKey, HpkeSealer, HpkeSuite,
};
use rustls::internal::msgs::enums::{HpkeAead, HpkeKdf, HpkeKem};
use rustls::internal::msgs::handshake::HpkeSymmetricCipherSuite;
use rustls::Error;

// ── 参数（RFC 9180 §7.1-7.3 / §5.2）──────────────────────────────────────────

/// DHKEM(X25519, HKDF-SHA256) 的 KEM ID。
const KEM_ID: u16 = 0x0020;
/// HKDF-SHA256 的 KDF ID。
const KDF_ID: u16 = 0x0001;
/// KEM shared_secret 长度（X25519 KEM 的 Nsecret）。
const N_SECRET: usize = 32;
/// AEAD nonce 长度（三个 AEAD 的 Nn 均为 12）。
const N_NONCE: usize = 12;
/// AEAD tag 长度（三个 AEAD 的 Nt 均为 16）。
const N_TAG: usize = 16;
/// mode_base（RFC 9180 §5.1）。
const MODE_BASE: u8 = 0x00;

// ── Suite 定义 ───────────────────────────────────────────────────────────────

/// 一个具体的 HPKE suite：固定 KEM = X25519 / KDF = SHA256，按 AEAD 区分。
struct Suite {
    aead: HpkeAead,
}

impl std::fmt::Debug for Suite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HpkeSuite(X25519/HKDF-SHA256/{:?})", self.aead)
    }
}

impl Suite {
    /// KEM 层 suite_id：`"KEM" || I2OSP(kem_id, 2)`（RFC 9180 §4）。
    fn kem_suite_id(&self) -> [u8; 5] {
        let mut id = [0u8; 5];
        id[..3].copy_from_slice(b"KEM");
        id[3..].copy_from_slice(&KEM_ID.to_be_bytes());
        id
    }

    /// HPKE 层 suite_id：`"HPKE" || kem || kdf || aead`（RFC 9180 §5.1）。
    fn hpke_suite_id(&self) -> [u8; 10] {
        // HpkeAead 未提供 to-u16 访问器（enum 非 primitive repr），suite 值
        // 是固定 IANA 常量，直接映射。
        let aead_id: u16 = match self.aead {
            HpkeAead::AES_128_GCM => 0x0001,
            HpkeAead::AES_256_GCM => 0x0002,
            HpkeAead::CHACHA20_POLY_1305 => 0x0003,
            // 本模块从不构造 EXPORT_ONLY / Unknown suite，仅为穷尽匹配。
            _ => 0xFFFF,
        };
        let mut id = [0u8; 10];
        id[..4].copy_from_slice(b"HPKE");
        id[4..6].copy_from_slice(&KEM_ID.to_be_bytes());
        id[6..8].copy_from_slice(&KDF_ID.to_be_bytes());
        id[8..].copy_from_slice(&aead_id.to_be_bytes());
        id
    }

    /// HPKE 的 Extract（RFC 9180 §4）：`HMAC-Hash(salt, ikm)`。
    /// salt 为空时按 RFC 9180 补零到 Nh（不能直接用空 key 的 HMAC）。
    fn hmac_extract(salt: &[u8], ikm: &[u8]) -> Vec<u8> {
        let padded_salt: Vec<u8> = if salt.is_empty() {
            vec![0u8; 32]
        } else {
            salt.to_vec()
        };
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&padded_salt)
            .expect("HMAC accepts any key length");
        mac.update(ikm);
        mac.finalize().into_bytes().to_vec()
    }

    /// LabeledExtract（RFC 9180 §4）：`Extract(salt, "HPKE-v1" || suite_id || label || ikm)`。
    ///
    /// 注意必须取原始 extract 输出（PRK），不能用 `HKDF-Expand(PRK, "", Nh)`
    /// 代替 —— 两者不相等。
    fn labeled_extract(&self, suite_id: &[u8], salt: &[u8], label: &str, ikm: &[u8]) -> Vec<u8> {
        let mut labeled_ikm = Vec::with_capacity(7 + suite_id.len() + label.len() + ikm.len());
        labeled_ikm.extend_from_slice(b"HPKE-v1");
        labeled_ikm.extend_from_slice(suite_id);
        labeled_ikm.extend_from_slice(label.as_bytes());
        labeled_ikm.extend_from_slice(ikm);
        Self::hmac_extract(salt, &labeled_ikm)
    }

    /// LabeledExpand（RFC 9180 §4）：
    /// `Expand(prk, I2OSP(L,2) || "HPKE-v1" || suite_id || label || info, L)`。
    fn labeled_expand(
        &self,
        suite_id: &[u8],
        prk: &[u8],
        label: &str,
        info: &[u8],
        len: usize,
    ) -> Result<Vec<u8>, Error> {
        let mut labeled_info =
            Vec::with_capacity(2 + 7 + suite_id.len() + label.len() + info.len());
        labeled_info.extend_from_slice(&(len as u16).to_be_bytes());
        labeled_info.extend_from_slice(b"HPKE-v1");
        labeled_info.extend_from_slice(suite_id);
        labeled_info.extend_from_slice(label.as_bytes());
        labeled_info.extend_from_slice(info);
        let hk = Hkdf::<Sha256>::from_prk(prk)
            .map_err(|_| Error::General("hpke: invalid PRK length".into()))?;
        let mut okm = vec![0u8; len];
        hk.expand(&labeled_info, &mut okm)
            .map_err(|_| Error::General("hpke: expand overflow".into()))?;
        Ok(okm)
    }

    /// ExtractAndExpand（RFC 9180 §4.1 KEM 流程）：
    /// `shared_secret = LabeledExpand(LabeledExtract("", "eae_prk", dh), "shared_secret", kem_context, Nsecret)`。
    fn extract_and_expand(&self, dh: &[u8], kem_context: &[u8]) -> Result<Vec<u8>, Error> {
        let kem_suite_id = self.kem_suite_id();
        let eae_prk = self.labeled_extract(&kem_suite_id, b"", "eae_prk", dh);
        self.labeled_expand(
            &kem_suite_id,
            &eae_prk,
            "shared_secret",
            kem_context,
            N_SECRET,
        )
    }

    /// KEM 封装 Encap（RFC 9180 §4.1）：返回 (enc, shared_secret)。
    fn encap(&self, pk_r: &HpkePublicKey) -> Result<(EncapsulatedSecret, Vec<u8>), Error> {
        let sk_e = XStaticSecret::random_from_rng(rand::thread_rng());
        self.encap_with(&sk_e, pk_r)
    }

    /// Encap 的核心实现，允许注入固定 ephemeral 私钥（RFC 9180 测试向量
    /// 固定 ikmE，随机实现无法复现向量，测试需要注入）。
    fn encap_with(
        &self,
        sk_e: &XStaticSecret,
        pk_r: &HpkePublicKey,
    ) -> Result<(EncapsulatedSecret, Vec<u8>), Error> {
        let pk_r_bytes: [u8; 32] = pk_r
            .0
            .as_slice()
            .try_into()
            .map_err(|_| Error::General("hpke: recipient public key must be 32 bytes".into()))?;
        let pk_r = XPublicKey::from(pk_r_bytes);
        let pk_e = XPublicKey::from(sk_e);
        let dh = sk_e.diffie_hellman(&pk_r);
        let mut kem_context = Vec::with_capacity(64);
        kem_context.extend_from_slice(pk_e.as_bytes());
        kem_context.extend_from_slice(pk_r.as_bytes());
        let shared_secret = self.extract_and_expand(dh.as_bytes(), &kem_context)?;
        Ok((
            EncapsulatedSecret(pk_e.as_bytes().to_vec()),
            shared_secret,
        ))
    }

    /// KEM 解封装 Decap（RFC 9180 §4.1）：返回 shared_secret。
    fn decap(&self, enc: &EncapsulatedSecret, sk_r: &HpkePrivateKey) -> Result<Vec<u8>, Error> {
        let enc_bytes: [u8; 32] = enc
            .0
            .as_slice()
            .try_into()
            .map_err(|_| Error::General("hpke: encapsulated key must be 32 bytes".into()))?;
        let sk_r_bytes: [u8; 32] = sk_r
            .secret_bytes()
            .try_into()
            .map_err(|_| Error::General("hpke: recipient private key must be 32 bytes".into()))?;
        let sk_r = XStaticSecret::from(sk_r_bytes);
        let pk_e = XPublicKey::from(enc_bytes);
        let pk_rm = XPublicKey::from(&sk_r);
        let dh = sk_r.diffie_hellman(&pk_e);
        let mut kem_context = Vec::with_capacity(64);
        kem_context.extend_from_slice(enc.0.as_slice());
        kem_context.extend_from_slice(pk_rm.as_bytes());
        self.extract_and_expand(dh.as_bytes(), &kem_context)
    }

    /// KeySchedule mode_base（RFC 9180 §5.1），返回 (key, base_nonce)。
    fn key_schedule(
        &self,
        shared_secret: &[u8],
        info: &[u8],
    ) -> Result<(Vec<u8>, [u8; N_NONCE]), Error> {
        let suite_id = self.hpke_suite_id();
        let psk_id_hash = self.labeled_extract(&suite_id, b"", "psk_id_hash", b"");
        let info_hash = self.labeled_extract(&suite_id, b"", "info_hash", info);
        let mut context = Vec::with_capacity(1 + psk_id_hash.len() + info_hash.len());
        context.push(MODE_BASE);
        context.extend_from_slice(&psk_id_hash);
        context.extend_from_slice(&info_hash);
        // base 模式无 PSK：secret = LabeledExtract(shared_secret, "secret", "")。
        let secret = self.labeled_extract(&suite_id, shared_secret, "secret", b"");
        let nk = match self.aead {
            HpkeAead::AES_128_GCM => 16,
            HpkeAead::AES_256_GCM => 32,
            HpkeAead::CHACHA20_POLY_1305 => 32,
            other => {
                return Err(Error::General(format!(
                    "hpke: unsupported AEAD id {other:?}"
                )))
            }
        };
        let key = self.labeled_expand(&suite_id, &secret, "key", &context, nk)?;
        let base_nonce_vec = self.labeled_expand(&suite_id, &secret, "base_nonce", &context, N_NONCE)?;
        let mut base_nonce = [0u8; N_NONCE];
        base_nonce.copy_from_slice(&base_nonce_vec);
        Ok((key, base_nonce))
    }
}

// ── AEAD 上下文（带 sequence number 的 nonce 推进，RFC 9180 §5.2）────────────

/// 发送/接收上下文：key + base_nonce + 单调递增 seq。
/// nonce = base_nonce XOR I2OSP(seq, Nn)；每个 seal/open 后 seq += 1。
#[derive(Debug)]
struct AeadCtx {
    aead: HpkeAead,
    key: Vec<u8>,
    base_nonce: [u8; N_NONCE],
    seq: u64,
}

impl AeadCtx {
    fn new(aead: HpkeAead, key: Vec<u8>, base_nonce: [u8; N_NONCE]) -> Self {
        Self { aead, key, base_nonce, seq: 0 }
    }

    fn compute_nonce(&self) -> Result<[u8; N_NONCE], Error> {
        if self.seq == u64::MAX {
            return Err(Error::General("hpke: sequence number exhausted".into()));
        }
        let mut seq_be = [0u8; N_NONCE];
        seq_be[4..].copy_from_slice(&self.seq.to_be_bytes());
        let mut nonce = self.base_nonce;
        for (n, s) in nonce.iter_mut().zip(seq_be.iter()) {
            *n ^= s;
        }
        Ok(nonce)
    }

    fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let nonce = self.compute_nonce()?;
        let mut buf = plaintext.to_vec();
        let tag = match self.aead {
            HpkeAead::AES_128_GCM => {
                let c = Aes128Gcm::new_from_slice(&self.key)
                    .map_err(|_| Error::General("hpke: bad AES-128 key length".into()))?;
                c.encrypt_in_place_detached((&nonce).into(), aad, &mut buf)
            }
            HpkeAead::AES_256_GCM => {
                let c = Aes256Gcm::new_from_slice(&self.key)
                    .map_err(|_| Error::General("hpke: bad AES-256 key length".into()))?;
                c.encrypt_in_place_detached((&nonce).into(), aad, &mut buf)
            }
            HpkeAead::CHACHA20_POLY_1305 => {
                let c = ChaCha20Poly1305::new_from_slice(&self.key)
                    .map_err(|_| Error::General("hpke: bad ChaCha20 key length".into()))?;
                c.encrypt_in_place_detached((&nonce).into(), aad, &mut buf)
            }
            other => {
                return Err(Error::General(format!(
                    "hpke: unsupported AEAD id {other:?}"
                )))
            }
        }
        .map_err(|_| Error::General("hpke: seal failed".into()))?;
        self.seq += 1;
        buf.extend_from_slice(tag.as_slice());
        Ok(buf)
    }

    fn open(&mut self, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        if ciphertext.len() < N_TAG {
            return Err(Error::General("hpke: ciphertext shorter than tag".into()));
        }
        let nonce = self.compute_nonce()?;
        let split = ciphertext.len() - N_TAG;
        let mut buf = ciphertext[..split].to_vec();
        let tag = aes_gcm::Tag::from_slice(&ciphertext[split..]);
        let result = match self.aead {
            HpkeAead::AES_128_GCM => {
                let c = Aes128Gcm::new_from_slice(&self.key)
                    .map_err(|_| Error::General("hpke: bad AES-128 key length".into()))?;
                c.decrypt_in_place_detached((&nonce).into(), aad, &mut buf, tag)
            }
            HpkeAead::AES_256_GCM => {
                let c = Aes256Gcm::new_from_slice(&self.key)
                    .map_err(|_| Error::General("hpke: bad AES-256 key length".into()))?;
                c.decrypt_in_place_detached((&nonce).into(), aad, &mut buf, tag)
            }
            HpkeAead::CHACHA20_POLY_1305 => {
                let c = ChaCha20Poly1305::new_from_slice(&self.key)
                    .map_err(|_| Error::General("hpke: bad ChaCha20 key length".into()))?;
                c.decrypt_in_place_detached((&nonce).into(), aad, &mut buf, tag)
            }
            other => {
                return Err(Error::General(format!(
                    "hpke: unsupported AEAD id {other:?}"
                )))
            }
        };
        if result.is_err() {
            return Err(Error::General("hpke: open failed".into()));
        }
        self.seq += 1;
        Ok(buf)
    }
}

impl HpkeSealer for AeadCtx {
    fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        AeadCtx::seal(self, aad, plaintext)
    }
}

impl HpkeOpener for AeadCtx {
    fn open(&mut self, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        AeadCtx::open(self, aad, ciphertext)
    }
}

// ── Hpke trait 实现 ──────────────────────────────────────────────────────────

impl Hpke for Suite {
    fn seal(
        &self,
        info: &[u8],
        aad: &[u8],
        plaintext: &[u8],
        pub_key: &HpkePublicKey,
    ) -> Result<(EncapsulatedSecret, Vec<u8>), Error> {
        let (enc, shared_secret) = self.encap(pub_key)?;
        let (key, base_nonce) = self.key_schedule(&shared_secret, info)?;
        let mut ctx = AeadCtx::new(self.aead, key, base_nonce);
        let ct = ctx.seal(aad, plaintext)?;
        Ok((enc, ct))
    }

    fn setup_sealer(
        &self,
        info: &[u8],
        pub_key: &HpkePublicKey,
    ) -> Result<(EncapsulatedSecret, Box<dyn HpkeSealer + 'static>), Error> {
        let (enc, shared_secret) = self.encap(pub_key)?;
        let (key, base_nonce) = self.key_schedule(&shared_secret, info)?;
        Ok((enc, Box::new(AeadCtx::new(self.aead, key, base_nonce))))
    }

    fn open(
        &self,
        enc: &EncapsulatedSecret,
        info: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
        secret_key: &HpkePrivateKey,
    ) -> Result<Vec<u8>, Error> {
        let shared_secret = self.decap(enc, secret_key)?;
        let (key, base_nonce) = self.key_schedule(&shared_secret, info)?;
        let mut ctx = AeadCtx::new(self.aead, key, base_nonce);
        ctx.open(aad, ciphertext)
    }

    fn setup_opener(
        &self,
        enc: &EncapsulatedSecret,
        info: &[u8],
        secret_key: &HpkePrivateKey,
    ) -> Result<Box<dyn HpkeOpener + 'static>, Error> {
        let shared_secret = self.decap(enc, secret_key)?;
        let (key, base_nonce) = self.key_schedule(&shared_secret, info)?;
        Ok(Box::new(AeadCtx::new(self.aead, key, base_nonce)))
    }

    fn generate_key_pair(&self) -> Result<(HpkePublicKey, HpkePrivateKey), Error> {
        let sk = XStaticSecret::random_from_rng(rand::thread_rng());
        let pk = XPublicKey::from(&sk);
        Ok((
            HpkePublicKey(pk.as_bytes().to_vec()),
            HpkePrivateKey::from(sk.as_bytes().to_vec()),
        ))
    }

    fn suite(&self) -> HpkeSuite {
        HpkeSuite {
            kem: HpkeKem::DHKEM_X25519_HKDF_SHA256,
            sym: HpkeSymmetricCipherSuite {
                kdf_id: HpkeKdf::HKDF_SHA256,
                aead_id: self.aead,
            },
        }
    }
}

/// ECH 可用的 HPKE suite 集合（DHKEM_X25519_HKDF_SHA256 + 三个 AEAD）。
///
/// 传给 [`rustls::client::EchConfig::new`] 的 `hpke_suites` 参数；rustls 从
/// ECHConfigList 中选择与此处兼容的第一条配置。
pub static ECH_HPKE_SUITES: &[&dyn Hpke] = &[&X25519_AES128GCM, &X25519_AES256GCM, &X25519_CHACHA20];

static X25519_AES128GCM: Suite = Suite { aead: HpkeAead::AES_128_GCM };
static X25519_AES256GCM: Suite = Suite { aead: HpkeAead::AES_256_GCM };
static X25519_CHACHA20: Suite = Suite { aead: HpkeAead::CHACHA20_POLY_1305 };

// ── 测试：RFC 9180 Appendix A.1 官方向量 ─────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::crypto::hpke::Hpke;

    const INFO: &str = "4f6465206f6e2061204772656369616e2055726e";
    const SK_EM: &str = "52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736";
    const SK_RM: &str = "4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8";
    const PK_RM: &str = "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d";
    const PK_EM: &str = "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431";
    const KEY: &str = "4531685d41d65f03dc48f6b8302c05b0";
    const PT: &str = "4265617574792069732074727574682c20747275746820626561757479";
    const CT_SEQ0: &str = concat!(
        "f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a9",
        "6d8770ac83d07bea87e13c512a"
    );
    const CT_SEQ1: &str = concat!(
        "af2d7e9ac9ae7e270f46ba1f975be53c09f8d875bdc8535458c2494e8a6eab25",
        "1c03d0c22a56b8ca42c2063b84"
    );

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn aad(seq: usize) -> String {
        format!("Count-{seq}")
    }

    /// A.1.1（DHKEM_X25519_HKDF_SHA256 + HKDF-SHA256 + AES-128-GCM）：
    /// 注入 RFC 固定的 ikmE，enc 必须等于 pkEm，一次性 seal（seq=0）输出
    /// 必须与 RFC 密文一致。
    #[test]
    fn rfc9180_a1_1_seal_matches_vector() {
        let suite = &X25519_AES128GCM;
        let sk_e_bytes: [u8; 32] = hex(SK_EM).try_into().unwrap();
        let sk_e = XStaticSecret::from(sk_e_bytes);
        let (enc, shared_secret) = suite
            .encap_with(&sk_e, &HpkePublicKey(hex(PK_RM)))
            .unwrap();
        assert_eq!(enc.0, hex(PK_EM), "enc must equal pkEm");
        let (key, base_nonce) = suite.key_schedule(&shared_secret, &hex(INFO)).unwrap();
        assert_eq!(key, hex(KEY), "key must match RFC key schedule output");
        let mut ctx = AeadCtx::new(HpkeAead::AES_128_GCM, key, base_nonce);
        let ct = ctx.seal(aad(0).as_bytes(), &hex(PT)).unwrap();
        assert_eq!(ct, hex(CT_SEQ0));
    }

    /// A.1.1：open（decap + seq=0）还原明文。
    #[test]
    fn rfc9180_a1_1_open_matches_vector() {
        let suite = &X25519_AES128GCM;
        let pt = suite
            .open(
                &EncapsulatedSecret(hex(PK_EM)),
                &hex(INFO),
                aad(0).as_bytes(),
                &hex(CT_SEQ0),
                &HpkePrivateKey::from(hex(SK_RM)),
            )
            .unwrap();
        assert_eq!(pt, hex(PT));
    }

    /// A.1.1：注入固定 ikmE 的 sealer 上下文按 seq 0/1 推进 nonce，两次输出
    /// 与 RFC sequence number 0/1 的密文逐一对应。
    #[test]
    fn rfc9180_a1_1_sealer_context_sequence() {
        let suite = &X25519_AES128GCM;
        let sk_e_bytes: [u8; 32] = hex(SK_EM).try_into().unwrap();
        let sk_e = XStaticSecret::from(sk_e_bytes);
        let (enc, shared_secret) = suite
            .encap_with(&sk_e, &HpkePublicKey(hex(PK_RM)))
            .unwrap();
        assert_eq!(enc.0, hex(PK_EM));
        let (key, base_nonce) = suite.key_schedule(&shared_secret, &hex(INFO)).unwrap();
        let mut sealer = AeadCtx::new(HpkeAead::AES_128_GCM, key, base_nonce);
        let ct0 = sealer.seal(aad(0).as_bytes(), &hex(PT)).unwrap();
        let ct1 = sealer.seal(aad(1).as_bytes(), &hex(PT)).unwrap();
        assert_eq!(ct0, hex(CT_SEQ0));
        assert_eq!(ct1, hex(CT_SEQ1));
    }

    /// 三个 AEAD suite 全部走一遍 seal → open 往返（随机密钥对）。
    #[test]
    fn roundtrip_all_suites() {
        for suite in ECH_HPKE_SUITES {
            let (pk, sk) = suite.generate_key_pair().unwrap();
            let (enc, ct) = suite
                .seal(b"info", b"aad", b"hello ech", &pk)
                .unwrap();
            let pt = suite
                .open(&enc, b"info", b"aad", &ct, &sk)
                .unwrap();
            assert_eq!(pt, b"hello ech");
        }
    }

    /// opener 上下文与 sealer 上下文按相同 seq 推进，可多次往返。
    #[test]
    fn context_roundtrip_multiple() {
        let suite = &X25519_AES128GCM;
        let (pk, sk) = suite.generate_key_pair().unwrap();
        let (enc, mut sealer) = suite.setup_sealer(b"info", &pk).unwrap();
        let mut opener = suite.setup_opener(&enc, b"info", &sk).unwrap();
        for i in 0..3u64 {
            let aad = format!("aad-{i}");
            let pt = format!("msg-{i}");
            let ct = sealer.seal(aad.as_bytes(), pt.as_bytes()).unwrap();
            assert_eq!(opener.open(aad.as_bytes(), &ct).unwrap(), pt.as_bytes());
        }
    }

    /// generate_key_pair 自洽测试的辅助：sk 标量派生公钥（正确路径：
    /// 从 StaticSecret 计算，而不是把标量字节当曲线点）。
    #[test]
    fn generate_key_pair_consistent() {
        let suite = &X25519_AES128GCM;
        let (pk, sk) = suite.generate_key_pair().unwrap();
        let sk_bytes: [u8; 32] = sk.secret_bytes().try_into().unwrap();
        let derived = XPublicKey::from(&XStaticSecret::from(sk_bytes));
        assert_eq!(derived.as_bytes(), pk.0.as_slice());
    }
}
