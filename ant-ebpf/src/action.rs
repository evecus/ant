//! TC verdict helpers. Same convention as honk's `action.rs`.

use aya_ebpf::cty::c_long;

pub type Verdict = Result<c_long, c_long>;

pub const TC_ACT_OK: c_long = 0;
pub const TC_ACT_SHOT: c_long = 2;
pub const TC_ACT_REDIRECT: c_long = 7;
pub const TC_ACT_UNSPEC: c_long = -1;

#[inline(always)]
pub fn flatten(v: Verdict) -> i32 {
    match v {
        Ok(a) | Err(a) => a as i32,
    }
}
