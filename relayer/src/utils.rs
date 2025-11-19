use ruint::aliases::U256;
use serde::{ser::SerializeSeq, Serializer};

pub fn ser_be32_as_dec<S>(v: &[u8; 32], s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let n = U256::from_be_bytes(*v);
    s.serialize_str(&n.to_string())
}

pub fn ser_arr_be32_as_dec<S>(v: &[[u8; 32]], s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut seq = s.serialize_seq(Some(v.len()))?;
    for b in v {
        let n = U256::from_be_bytes(*b);
        seq.serialize_element(&n.to_string())?;
    }
    seq.end()
}

pub fn ser_bool_as_u8<S>(b: &bool, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    s.serialize_u8(*b as u8)
}
