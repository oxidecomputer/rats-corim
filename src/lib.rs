// From https://datatracker.ietf.org/doc/draft-ietf-rats-corim/
use ciborium::Value;
use serde::{Deserialize, Serialize};
#[macro_use]
mod serde_workaround;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("incorrect value, tag {0} expected {1}")]
    WrongValue(String, String),
    #[error("integer too big")]
    IntegerTooBig,
    #[error("incorrect array length")]
    BadArrayLen,
    #[error("deserialization error {0}")]
    Deserialize(String),
    #[error("Tag {0} did not match")]
    IncorrectTag(u64),
    #[error("Io {0}")]
    Io(std::io::Error),
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(try_from = "Value", into = "Value")]
pub enum TaggedBytes {
    Tagged(u64, Vec<u8>),
    Bytes(Vec<u8>),
}

impl std::fmt::Display for TaggedBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TaggedBytes::Tagged(t, v) => write!(f, "{};{}", t, hex::encode(&v)),
            TaggedBytes::Bytes(b) => write!(f, "{}", hex::encode(&b)),
        }
    }
}

impl From<TaggedBytes> for Value {
    fn from(val: TaggedBytes) -> Self {
        match val {
            TaggedBytes::Bytes(b) => Value::Bytes(b),
            TaggedBytes::Tagged(t, v) => Value::Tag(t, Box::new(Value::Bytes(v))),
        }
    }
}

impl TryFrom<Value> for TaggedBytes {
    type Error = Error;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        match value {
            Value::Tag(t, v) => match *v {
                Value::Bytes(vec) => Ok(Self::Tagged(t, vec)),
                _ => Err(Error::WrongValue(
                    "TaggedBytes".to_string(),
                    "bytes".to_string(),
                )),
            },
            Value::Bytes(vec) => Ok(Self::Bytes(vec)),
            _ => Err(Error::WrongValue(
                "TaggedBytes".to_string(),
                "bytes or tag".to_string(),
            )),
        }
    }
}

// This is a very common set of choices
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(try_from = "Value", into = "Value")]
pub enum TypeChoice {
    UInt(usize),
    Text(String),
    Uuid(Vec<u8>),
    Oid(Vec<u8>),
}

// Section 7.4
const UUID_TAG: u64 = 37;

// Section 7.6
const OID_TAG: u64 = 111;

impl std::fmt::Display for TypeChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TypeChoice::UInt(u) => write!(f, "int;{}", u),
            TypeChoice::Text(s) => write!(f, "text;{}", s),
            TypeChoice::Uuid(u) => write!(f, "uuid;{}", hex::encode(&u)),
            TypeChoice::Oid(o) => write!(f, "oid;{}", hex::encode(&o)),
        }
    }
}

impl From<TypeChoice> for Value {
    fn from(val: TypeChoice) -> Self {
        use ciborium::value::Integer;
        match val {
            TypeChoice::UInt(i) => Value::Integer(Integer::from(i)),
            TypeChoice::Text(s) => Value::Text(s),
            TypeChoice::Uuid(v) => Value::Tag(UUID_TAG, Box::new(Value::Bytes(v))),
            TypeChoice::Oid(v) => Value::Tag(OID_TAG, Box::new(Value::Bytes(v))),
        }
    }
}

impl TryFrom<Value> for TypeChoice {
    type Error = Error;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        match value {
            // TODO check the tag value
            Value::Tag(t, v) => match *v {
                Value::Bytes(vec) => match t {
                    UUID_TAG => Ok(Self::Uuid(vec)),
                    OID_TAG => Ok(Self::Oid(vec)),
                    _ => Err(Error::IncorrectTag(t)),
                },

                _ => Err(Error::WrongValue(
                    "TypeChoice".to_string(),
                    "bytes".to_string(),
                )),
            },
            Value::Integer(i) => Ok(Self::UInt(i.try_into().map_err(|_| Error::IntegerTooBig)?)),
            Value::Text(s) => Ok(Self::Text(s)),
            _ => Err(Error::WrongValue(
                "TypeChoice".to_string(),
                "tag, integer, or text".to_string(),
            )),
        }
    }
}

#[test]
fn type_choice_tests() {
    let int_value = ciborium::cbor!(1234).unwrap();

    let text_value = ciborium::cbor!("this is text").unwrap();

    let uid_value = Value::Tag(UUID_TAG, Box::new(Value::Bytes(vec![0, 1, 2, 3, 4])));

    let result = match int_value.deserialized() {
        Ok(v) => match v {
            TypeChoice::UInt(_) => v,
            _ => panic!("wrong type"),
        },
        Err(_) => panic!("did not deserialze"),
    };

    assert!(int_value == Value::serialized(&result).unwrap());

    let result = match text_value.deserialized() {
        Ok(v) => match v {
            TypeChoice::Text(_) => v,
            _ => panic!("wrong type"),
        },
        Err(_) => panic!("did not deserialze"),
    };

    assert!(text_value == Value::serialized(&result).unwrap());

    let result = match uid_value.deserialized() {
        Ok(v) => match v {
            TypeChoice::Uuid(_) => v,
            _ => panic!("wrong type"),
        },
        Err(_) => panic!("did not deserialze"),
    };

    assert!(uid_value == Value::serialized(&result).unwrap());
}

// 5.1.4.1.4.3.  Version
serde_workaround! {
#[derive(Debug, Default, Clone)]
pub struct VersionMap {
    #[serde(rename = 0x0)]
    version: String,
    #[serde(rename = 0x1)]
    version_scheme: usize,
}

}

#[test]
fn test_version_map() {
    use ciborium::cbor;

    let map = ciborium::cbor!( {
        0 => "0.0.0",
        1 => 3,

    })
    .unwrap();

    let _: VersionMap = map.deserialized().unwrap();

    let sample = VersionMap {
        version: "0.0.0".to_string(),
        version_scheme: 3,
    };

    let serialized = Value::serialized(&sample).unwrap();

    assert!(serialized == map);
}

// 7.7.  Digest
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Digest {
    alg: usize,
    val: TaggedBytes,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(try_from = "Vec<Value>", into = "Value")]
pub struct WrappedDigests {
    wrapped: Vec<Digest>,
}

impl std::fmt::Display for WrappedDigests {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for d in &self.wrapped {
            match &d.val {
                TaggedBytes::Bytes(b) => {
                    write!(f, "{};{}", d.alg, hex::encode(&b))?;
                }
                _ => (),
            }
        }
        Ok(())
    }
}

impl From<WrappedDigests> for Value {
    fn from(val: WrappedDigests) -> Value {
        Value::Array(
            val.wrapped
                .into_iter()
                .flat_map(|x| {
                    vec![
                        Value::Integer(ciborium::value::Integer::from(x.alg)),
                        x.val.into(),
                    ]
                })
                .collect::<Vec<_>>(),
        )
    }
}

impl TryFrom<Vec<Value>> for WrappedDigests {
    type Error = Error;

    fn try_from(value: Vec<Value>) -> Result<Self, Self::Error> {
        if value.len() % 2 != 0 {
            return Err(Self::Error::BadArrayLen);
        }
        let mut wrapped = vec![];
        for entries in value.chunks(2) {
            let alg: usize = entries[0]
                .deserialized()
                .map_err(|_| Error::Deserialize("alg".to_string()))?;
            let val: TaggedBytes = entries[1]
                .deserialized()
                .map_err(|_| Error::Deserialize("val".to_string()))?;
            wrapped.push(Digest { alg, val });
        }
        Ok(WrappedDigests { wrapped })
    }
}

#[test]
fn test_digests() {
    use ciborium::value::Integer;

    let digests = Value::Array(vec![
        Value::Integer(Integer::from(1000)),
        Value::Bytes(vec![1, 2, 3, 4, 5, 6, 7, 8]),
        Value::Integer(Integer::from(2000)),
        Value::Bytes(vec![10, 11, 12, 13, 14, 15, 16, 17]),
    ]);

    let a: WrappedDigests = digests.deserialized().unwrap();

    let b = Value::serialized(&a).unwrap();

    if digests != b {
        panic!(
            "mismatch expected: {} found: {}",
            pretty_print(digests),
            pretty_print(b)
        );
    }
}

// 5.1.4.1.4.5.  Flags
serde_workaround! {
#[derive(Debug, Default, Clone)]
pub struct FlagsMap {
    #[serde(rename = 0x0)]
    is_configured: bool,
    #[serde(rename = 0x1)]
    is_secure: bool,
    #[serde(rename = 0x2)]
    is_recovery: bool,
    #[serde(rename = 0x3)]
    is_debug: bool,
    #[serde(rename = 0x4)]
    is_replay_protected: bool,
    #[serde(rename = 0x5)]
    is_integrity_protected: bool,
    #[serde(rename = 0x6)]
    is_runtime_meas: bool,
    #[serde(rename = 0x7)]
    is_immutible: bool,
    #[serde(rename = 0x8)]
    is_tcb: bool,
    #[serde(rename = 0x9)]
    is_confidentiality_protected: bool,
}
}

#[test]
fn test_flags_map() {
    use ciborium::cbor;

    let map = ciborium::cbor!( {
        0 => false,
        1 => true,
        2 => false,
        3 => true,
        4 => false,
        5 => true,
        6 => false,
        7 => true,
        8 => false,
        9 => true,
    })
    .unwrap();

    let result: FlagsMap = map.deserialized().unwrap();

    assert!(map == Value::serialized(&result).unwrap());
}

const SVN_TAG: u64 = 552;
const MIN_SVN_TAG: u64 = 553;

// 5.1.4.1.4.4.  Security Version Number
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(try_from = "Value", into = "Value")]
pub enum SvnTypeChoice {
    Svn(usize),
    TaggedSvn(usize),
    MinSvn(usize),
}

impl From<SvnTypeChoice> for Value {
    fn from(val: SvnTypeChoice) -> Value {
        use ciborium::value::Integer;

        match val {
            SvnTypeChoice::Svn(u) => Value::Integer(Integer::from(u)),
            SvnTypeChoice::TaggedSvn(u) => {
                Value::Tag(SVN_TAG, Box::new(Value::Integer(Integer::from(u))))
            }
            SvnTypeChoice::MinSvn(u) => {
                Value::Tag(MIN_SVN_TAG, Box::new(Value::Integer(Integer::from(u))))
            }
        }
    }
}

impl TryFrom<Value> for SvnTypeChoice {
    type Error = Error;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        match value {
            Value::Tag(t, v) => {
                let val = match *v {
                    Value::Integer(i) => i,
                    _ => {
                        return Err(Error::WrongValue(
                            "SvnTypeChoice".to_string(),
                            "Integer".to_string(),
                        ))
                    }
                };
                match t {
                    SVN_TAG => Ok(SvnTypeChoice::TaggedSvn(
                        val.try_into().map_err(|_| Error::IntegerTooBig)?,
                    )),
                    MIN_SVN_TAG => Ok(SvnTypeChoice::MinSvn(
                        val.try_into().map_err(|_| Error::IntegerTooBig)?,
                    )),
                    t => Err(Error::IncorrectTag(t)),
                }
            }
            Value::Integer(i) => Ok(SvnTypeChoice::Svn(
                i.try_into().map_err(|_| Error::IntegerTooBig)?,
            )),
            _ => Err(Error::WrongValue(
                "SvnTypeChoice".to_string(),
                "Tag or Integer".to_string(),
            )),
        }
    }
}

// 5.1.4.1.4.2.  Measurement Values
serde_workaround! {
#[derive(Debug, Clone)]
pub struct MeasurementValuesMap {
    #[serde(rename = 0x0, default, skip_serializing_if = Option::is_none)]
    version: Option<VersionMap>,
    #[serde(rename = 0x1, default, skip_serializing_if = Option::is_none)]
    svn: Option<SvnTypeChoice>,
    #[serde(rename = 0x2, default, skip_serializing_if = Option::is_none)]
    digests: Option<Vec<WrappedDigests>>,
    #[serde(rename = 0x3, default, skip_serializing_if = Option::is_none)]
    flags: Option<FlagsMap>,
    #[serde(rename = 0x4, default, skip_serializing_if = Option::is_none)]
    raw_value: Option<TaggedBytes>,
    #[serde(rename = 0x5, default, skip_serializing_if = Option::is_none)]
    raw_value_mask: Option<Vec<u8>>,
    #[serde(rename = 0x6, default, skip_serializing_if = Option::is_none)]
    mac_addr: Option<Vec<u8>>,
    #[serde(rename = 0x7, default, skip_serializing_if = Option::is_none)]
    ip_addr: Option<Vec<u8>>,
    #[serde(rename = 0x8, default, skip_serializing_if = Option::is_none)]
    serial_number: Option<String>,
    #[serde(rename = 0x9, default, skip_serializing_if = Option::is_none)]
    ueid: Option<String>,
    #[serde(rename = 0xa, default, skip_serializing_if = Option::is_none)]
    uuid: Option<String>,
    #[serde(rename = 0xb, default, skip_serializing_if = Option::is_none)]
    name: Option<String>,
    #[serde(rename = 0xc, default, skip_serializing_if = Option::is_none)]
    cryptokeys: Option<String>,
    //#[serde(rename = 0xd)]
    // TODO see 5.1.4.1.6.  Integrity Registers
    //integrity_registers:
}
}

impl std::fmt::Display for MeasurementValuesMap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Add more fields later
        if let Some(digests) = &self.digests {
            for d in digests {
                write!(f, "{}", d)?;
            }
        }
        Ok(())
    }
}

impl MeasurementValuesMap {
    fn new_digest(alg: usize, val: Vec<u8>) -> Self {
        MeasurementValuesMap {
            version: None,
            svn: None,
            flags: None,
            raw_value: None,
            raw_value_mask: None,
            mac_addr: None,
            ip_addr: None,
            serial_number: None,
            ueid: None,
            uuid: None,
            name: None,
            cryptokeys: None,
            digests: Some(vec![WrappedDigests {
                wrapped: vec![Digest {
                    alg,
                    val: TaggedBytes::Bytes(val),
                }],
            }]),
        }
    }
}

// 5.1.4.  Triples
// TODO add the rest of the fields, these all look very similar to `reference-triple`
// but with slight variations
serde_workaround! {
#[derive(Debug, Clone)]
pub struct Triple {
    #[serde(rename = 0x0, default, skip_serializing_if = Vec::is_empty)]
    reference_triple: Vec<WrappedReferenceTripleRecord>,
    #[serde(rename = 0x1, default, skip_serializing_if = Vec::is_empty)]
    endorsed_triple: Vec<WrappedReferenceTripleRecord>,
}
}

impl std::fmt::Display for Triple {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // yeah add more later
        for r in &self.reference_triple {
            write!(f, "{}", r)?;
        }
        Ok(())
    }
}

// 5.1.4.1.1.  Environment Class
serde_workaround! {
#[derive(Debug, Clone)]
pub struct ClassMap {
    #[serde(rename = 0x0, default, skip_serializing_if = Option::is_none)]
    class_id: Option<TypeChoice>,
    #[serde(rename = 0x1, default, skip_serializing_if = Option::is_none)]
    vendor: Option<String>,
    #[serde(rename = 0x2, default, skip_serializing_if = Option::is_none)]
    model: Option<String>,
    #[serde(rename = 0x3, default, skip_serializing_if = Option::is_none)]
    layer: Option<usize>,
    #[serde(rename = 0x4, default, skip_serializing_if = Option::is_none)]
    index: Option<usize>,
}
}

impl std::fmt::Display for ClassMap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(vendor) = &self.vendor {
            write!(f, "{}", vendor)?;
        }
        Ok(())
    }
}

impl ClassMap {
    fn with_vendor(vendor: String) -> Self {
        ClassMap {
            class_id: None,
            vendor: Some(vendor),
            model: None,
            layer: None,
            index: None,
        }
    }
}

// 5.1.4.1.  Environments
serde_workaround! {
#[derive(Debug, Clone)]
pub struct EnvironmentMap {
    #[serde(rename = 0x0, default, skip_serializing_if = Option::is_none )]
    class: Option<ClassMap>,
    #[serde(rename = 0x1, default, skip_serializing_if = Option::is_none)]
    instance: Option<TypeChoice>,
    #[serde(rename = 0x2, default, skip_serializing_if = Option::is_none)]
    group: Option<TypeChoice>,
}
}

impl std::fmt::Display for EnvironmentMap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(class) = &self.class {
            write!(f, "{}", class)?;
        }
        Ok(())
    }
}

impl EnvironmentMap {
    fn with_vendor(vendor: String) -> Self {
        EnvironmentMap {
            class: Some(ClassMap::with_vendor(vendor)),
            instance: None,
            group: None,
        }
    }
}

// 5.1.4.2.  Reference Values Triple
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ReferenceTripleRecord {
    ref_env: EnvironmentMap,
    ref_claims: Vec<MeasurementMap>,
}

impl std::fmt::Display for ReferenceTripleRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Env: {}", self.ref_env)?;
        writeln!(f, "claims:")?;
        for c in &self.ref_claims {
            writeln!(f, "  {}", c)?;
        }
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(try_from = "Vec<Value>", into = "Value")]
pub struct WrappedReferenceTripleRecord {
    wrapped: Vec<ReferenceTripleRecord>,
}

impl std::fmt::Display for WrappedReferenceTripleRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for r in &self.wrapped {
            write!(f, "{}", r)?;
        }
        Ok(())
    }
}

impl From<WrappedReferenceTripleRecord> for Value {
    fn from(val: WrappedReferenceTripleRecord) -> Self {
        Value::Array(
            val.wrapped
                .into_iter()
                .flat_map(|x| {
                    vec![
                        Value::serialized(&x.ref_env).unwrap(),
                        Value::serialized(&x.ref_claims).unwrap(),
                    ]
                })
                .collect::<Vec<_>>(),
        )
    }
}

impl TryFrom<Vec<Value>> for WrappedReferenceTripleRecord {
    type Error = Error;

    fn try_from(value: Vec<Value>) -> Result<Self, Self::Error> {
        if value.len() % 2 != 0 {
            return Err(Error::BadArrayLen);
        }
        let mut wrapped = vec![];
        for entries in value.chunks(2) {
            let env: EnvironmentMap = entries[0]
                .deserialized()
                .map_err(|e| Error::Deserialize(format!("env {:?}", e)))?;
            let claims: Vec<MeasurementMap> = entries[1]
                .deserialized()
                .map_err(|e| Error::Deserialize(format!("claims {:?}", e)))?;
            wrapped.push(ReferenceTripleRecord {
                ref_env: env,
                ref_claims: claims,
            });
        }
        Ok(WrappedReferenceTripleRecord { wrapped })
    }
}

// 5.1.4.1.4.  Measurements
serde_workaround! {
#[derive(Debug, Clone)]
pub struct MeasurementMap {
    #[serde(rename = 0x0, default, skip_serializing_if = Option::is_none)]
    mkey: Option<TypeChoice>,
    #[serde(rename = 0x1)]
    mval: MeasurementValuesMap,
}
}

impl std::fmt::Display for MeasurementMap {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        if let Some(mkey) = &self.mkey {
            write!(f, "{} => ", mkey)?;
        }
        write!(f, "{}", self.mval)?;
        Ok(())
    }
}

impl MeasurementMap {
    fn new(mkey: String, alg: usize, val: Vec<u8>) -> Self {
        MeasurementMap {
            mkey: Some(TypeChoice::Text(mkey)),
            mval: MeasurementValuesMap::new_digest(alg, val),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(try_from = "Value", into = "Value")]
enum IdType {
    Id(String),
    Bytes(Vec<u8>),
}

impl std::fmt::Display for IdType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            IdType::Id(s) => write!(f, "{}", s),
            IdType::Bytes(b) => write!(f, "{}", hex::encode(&b)),
        }
    }
}

impl From<IdType> for Value {
    fn from(val: IdType) -> Self {
        match val {
            IdType::Id(s) => Value::Text(s),
            IdType::Bytes(b) => Value::Bytes(b),
        }
    }
}

impl TryFrom<Value> for IdType {
    type Error = Error;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        match value {
            Value::Text(s) => Ok(Self::Id(s)),
            Value::Bytes(b) => Ok(Self::Bytes(b)),
            _ => Err(Error::WrongValue(
                "IdType".to_string(),
                "Text or Bytes".to_string(),
            )),
        }
    }
}

// 7.2.  Entity
// XXX I don't think `role` is correct...
serde_workaround! {
#[derive(Debug, Clone)]
pub struct EntityMap {
    #[serde(rename = 0x0)]
    entity_name: String,
    #[serde(rename = 0x1, default, skip_serializing_if = Option::is_none)]
    reg_id: Option<TaggedUri>,
    #[serde(rename = 0x2, default, skip_serializing_if = Vec::is_empty)]
    role: Vec<usize>,
}
}

// 5.1.1.  Tag Identity
serde_workaround! {
#[derive(Debug, Clone)]
pub struct TagIdentityMap {
    #[serde(rename = 0x0)]
    id: IdType,
    #[serde(rename = 0x1, default, skip_serializing_if = Option::is_none)]
    version: Option<String>,
}
}

impl std::fmt::Display for TagIdentityMap {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.id)
    }
}

impl TagIdentityMap {
    fn new(id_map: String) -> Self {
        TagIdentityMap {
            id: IdType::Id(id_map),
            version: None,
        }
    }
}

// 5.1.3.  LinkedTag
serde_workaround! {
#[derive(Debug, Clone)]
pub struct LinkedTagMap {
    #[serde(rename = 0x0)]
    id: IdType,
    #[serde(rename = 0x1)]
    tag_rel: usize,
}
}

// 5.1.  Structure
serde_workaround! {
#[derive(Debug, Clone)]
pub struct Comid {
    #[serde(rename = 0x0, default, skip_serializing_if = Option::is_none)]
    language: Option<String>,
    #[serde(rename = 0x1)]
    tag_identity: TagIdentityMap,
    #[serde(rename = 0x2, default, skip_serializing_if = Option::is_none)]
    entities: Option<Vec<EntityMap>>,
    #[serde(rename = 0x3, default, skip_serializing_if = Option::is_none)]
    linked_tags: Option<Vec<LinkedTagMap>>,
    #[serde(rename = 0x4)]
    triples: Triple,
}
}

impl std::fmt::Display for Comid {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        writeln!(f, "tag-identity: {}", self.tag_identity.id)?;
        writeln!(f, "triples: {{ {} }}", self.triples)?;
        Ok(())
    }
}

impl Comid {
    fn new(tag_identity: String, triple: Triple) -> Self {
        Comid {
            language: None,
            tag_identity: TagIdentityMap::new(tag_identity),
            entities: None,
            linked_tags: None,
            triples: triple,
        }
    }
}

const COMID_TAG: u64 = 506;

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(try_from = "Value", into = "Value")]
pub struct WrappedComid {
    wrapped: Vec<Comid>,
}

impl std::fmt::Display for WrappedComid {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        for c in &self.wrapped {
            write!(f, "{}", c)?;
        }
        Ok(())
    }
}

impl From<WrappedComid> for Value {
    fn from(val: WrappedComid) -> Self {
        Value::Array(
            val.wrapped
                .into_iter()
                .map(|x| {
                    let mut b = vec![];
                    ciborium::into_writer(
                        &Value::Tag(COMID_TAG, Box::new(Value::serialized(&x).unwrap())),
                        &mut b,
                    )
                    .unwrap();
                    Value::Bytes(b)
                })
                .collect::<Vec<_>>(),
        )
    }
}

impl TryFrom<Value> for WrappedComid {
    type Error = Error;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        let mut wrapped = vec![];

        match value {
            Value::Array(arr) => {
                for a in arr {
                    match a {
                        Value::Bytes(b) => {
                            let c: Comid = ciborium::from_reader(&b[..])
                                .map_err(|e| Error::Deserialize(format!("comid {:?}", e)))?;
                            wrapped.push(c);
                        }
                        _ => {
                            return Err(Error::WrongValue(
                                "WrappedComid".to_string(),
                                "bytes".to_string(),
                            ))
                        }
                    }
                }
            }
            _ => {
                return Err(Error::WrongValue(
                    "WrappedComid".to_string(),
                    "array".to_string(),
                ))
            }
        }
        Ok(WrappedComid { wrapped })
    }
}

// See RFC 7049
const URI_TAG: u64 = 32;

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(try_from = "Value", into = "Value")]
pub enum TaggedUri {
    Uri(String),
}

impl From<TaggedUri> for Value {
    fn from(val: TaggedUri) -> Value {
        match val {
            TaggedUri::Uri(s) => Value::Tag(URI_TAG, Box::new(Value::Text(s))),
        }
    }
}

impl TryFrom<Value> for TaggedUri {
    type Error = Error;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        match value {
            Value::Tag(t, v) => {
                if t != URI_TAG {
                    return Err(Error::IncorrectTag(t));
                }
                match *v {
                    Value::Text(s) => Ok(TaggedUri::Uri(s)),
                    _ => Err(Error::WrongValue(
                        "TaggedUrl".to_string(),
                        "Text".to_string(),
                    )),
                }
            }
            _ => Err(Error::WrongValue(
                "TaggedUri".to_string(),
                "Tag".to_string(),
            )),
        }
    }
}

// 4.1.3.  Locator Map
serde_workaround! {
#[derive(Debug, Clone)]
pub struct Locator {
    #[serde(rename = 0x0)]
    href: TaggedUri,
    #[serde(rename = 0x1, default, skip_serializing_if = Option::is_none)]
    thumbprint: Option<WrappedDigests>,
}
}

// 7.3.  Validity
// XXX Need to check how these are actually stored
#[derive(Debug, Default, Deserialize, Serialize, Clone)]
struct Validity {
    not_before: String,
    not_after: String,
}

// 4.1.  CoRIM Map
serde_workaround! {
#[derive(Debug, Clone)]
pub struct Corim {
    #[serde(rename = 0x0)]
    id: String,
    #[serde(rename = 0x1)]
    tags: WrappedComid,
    #[serde(rename = 0x2, default, skip_serializing_if = Vec::is_empty)]
    dependent_rims: Vec<Locator>,
    #[serde(rename = 0x3, default, skip_serializing_if = Option::is_none)]
    profile: Option<String>,
    #[serde(rename = 0x4, default, skip_serializing_if = Option::is_none)]
    validity: Option<Validity>,
    #[serde(rename = 0x5, default, skip_serializing_if = Vec::is_empty)]
    corim_entities: Vec<EntityMap>,
}
}

impl std::fmt::Display for Corim {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        writeln!(f, "Corim {{")?;
        writeln!(f, "id: {}", self.id)?;
        writeln!(f, "{}", self.tags)?;
        writeln!(f, "}}")?;
        Ok(())
    }
}

impl Corim {
    fn new(id: String, tags: Comid) -> Self {
        Corim {
            id,
            tags: WrappedComid {
                wrapped: vec![tags],
            },
            dependent_rims: vec![],
            profile: None,
            validity: None,
            corim_entities: vec![],
        }
    }

    pub fn from_file(path: std::path::PathBuf) -> Result<Self, Error> {
        let bytes = std::fs::read(&path).map_err(Error::Io)?;
        ciborium::from_reader(&bytes[..])
            .map_err(|e| Error::Deserialize(format!("from file {:?}", e)))
    }

    pub fn iter_measurements(&self) -> impl Iterator<Item = Vec<u8>> {
        let comid = self.tags.wrapped.clone().into_iter();
        let reference_triple = comid.flat_map(|x| x.triples.reference_triple.into_iter());
        let reference_triple = reference_triple.flat_map(|x| x.wrapped.into_iter());
        let claims = reference_triple.flat_map(|x| x.ref_claims.into_iter());
        let digests = claims.flat_map(|x| {
            if let Some(v) = x.mval.digests {
                v.into_iter()
            } else {
                vec![].into_iter()
            }
        });
        let digests = digests.flat_map(|x| x.wrapped.into_iter());
        digests.into_iter().map(|x| match x.val {
            TaggedBytes::Bytes(v) => v,
            _ => unreachable!(),
        })
    }
}

// Internal structure used with `CorimBuilder`
struct MeasurementEntry {
    //digest: Digest,
    alg: usize,
    val: Vec<u8>,
    mkey: String,
}

pub struct CorimBuilder {
    hashes: Vec<MeasurementEntry>,
    vendor: Option<String>,
    tag_id: Option<String>,
}

impl CorimBuilder {
    pub fn new() -> Self {
        CorimBuilder {
            hashes: Vec::new(),
            vendor: None,
            tag_id: None,
        }
    }

    pub fn add_hash(&mut self, mkey: String, alg: usize, val: Vec<u8>) {
        self.hashes.push(MeasurementEntry { mkey, alg, val });
    }

    pub fn vendor(&mut self, vendor: String) {
        self.vendor = Some(vendor);
    }

    pub fn tag_id(&mut self, tag_id: String) {
        self.tag_id = Some(tag_id);
    }

    pub fn build(self) -> Corim {
        let maps = self
            .hashes
            .into_iter()
            .map(|entry| MeasurementMap::new(entry.mkey, entry.alg, entry.val))
            .collect();
        let record = ReferenceTripleRecord {
            ref_env: EnvironmentMap::with_vendor(self.vendor.unwrap()),
            ref_claims: maps,
        };

        let triple = Triple {
            reference_triple: vec![WrappedReferenceTripleRecord {
                wrapped: vec![record],
            }],
            endorsed_triple: vec![],
        };
        let comid = Comid::new(self.tag_id.unwrap(), triple);

        Corim::new("FIXME".to_string(), comid)
    }
}

// 4.2.2.1.  Signer Map
serde_workaround! {
#[derive(Debug, Clone)]
pub struct CorimSignerMap {
    #[serde(rename = 0x0)]
    signer_name: String,
    #[serde(rename = 0x1, default, skip_serializing_if = Option::is_none)]
    signer_uri: Option<String>,
}
}

// 4.2.2.  Meta Map
serde_workaround! {
#[derive(Debug, Clone)]
pub struct CorimMetaMap {
    #[serde(rename = 0x0)]
    signer: CorimSignerMap,
    #[serde(rename = 0x1, default, skip_serializing_if = Option::is_none)]
    signature_validity: Option<Validity>,
}
}
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(try_from = "Value", into = "Value")]
pub struct WrappedCorimMetaMap {
    wrapped: CorimMetaMap,
}

impl From<WrappedCorimMetaMap> for Value {
    fn from(val: WrappedCorimMetaMap) -> Self {
        let mut bytes = vec![];
        ciborium::into_writer(&val.wrapped, &mut bytes).unwrap();
        Value::Bytes(bytes)
    }
}

impl TryFrom<Value> for WrappedCorimMetaMap {
    type Error = Error;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        match value {
            Value::Bytes(b) => {
                let wrapped: CorimMetaMap = ciborium::from_reader(&b[..])
                    .map_err(|e| Error::Deserialize(format!("meta map {:?}", e)))?;
                Ok(WrappedCorimMetaMap { wrapped })
            }
            _ => Err(Error::WrongValue(
                "WrappedCorimMetaMap".to_string(),
                "Bytes".to_string(),
            )),
        }
    }
}

// 4.2.1.  Protected Header Map
serde_workaround! {
#[derive(Debug, Clone)]
pub struct ProtectedCorimHeaderMap {
    #[serde(rename = 0x1)]
    alg: isize,
    #[serde(rename = 0x3)]
    content_type: String,
    #[serde(rename = 0x4, default, skip_serializing_if = Vec::is_empty)]
    kid: Vec<u8>,
    #[serde(rename = 0x8)]
    corim_meta: WrappedCorimMetaMap,
}
}

// 4.2.3.  Unprotected CoRIM Header Map
//
//    unprotected-corim-header-map = {
//     * cose-label => cose-value
//  }
//
//
//   cose-label = int / tstr
//   cose-value = any
//
// This is just "be yourself and have fun :)" in spec form

const SIGNED_CORIM_TAG: u64 = 18;

// 4.2.  Signed CoRIM
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(try_from = "Value", into = "Value")]
pub struct SignedCorim {
    protected: ProtectedCorimHeaderMap,
    // This should be a `unprotected-corim-header-map` but see above
    unprotected: Value,
    payload: Corim,
    signature: Vec<u8>,
}

impl From<SignedCorim> for Value {
    fn from(val: SignedCorim) -> Self {
        let mut protected = vec![];
        ciborium::into_writer(&val.protected, &mut protected).unwrap();
        let mut payload = vec![];
        ciborium::into_writer(&val.payload, &mut payload).unwrap();
        Value::Tag(
            SIGNED_CORIM_TAG,
            Box::new(Value::Array(vec![
                Value::Bytes(protected),
                val.unprotected,
                Value::Bytes(payload),
                Value::Bytes(val.signature),
            ])),
        )
    }
}

impl TryFrom<Value> for SignedCorim {
    type Error = Error;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        match value {
            Value::Tag(tag, tt) => {
                if tag != SIGNED_CORIM_TAG {
                    return Err(Error::IncorrectTag(tag));
                }
                match *tt {
                    Value::Array(vals) => {
                        if vals.len() != 4 {
                            return Err(Error::BadArrayLen);
                        }

                        let protected: ProtectedCorimHeaderMap = match &vals[0] {
                            Value::Bytes(b) => {
                                let internal: ProtectedCorimHeaderMap =
                                    ciborium::from_reader(&b[..]).map_err(|e| {
                                        Error::Deserialize(format!("protected {:?}", e))
                                    })?;
                                internal
                            }
                            _ => {
                                return Err(Error::WrongValue(
                                    "SignedCorim".to_string(),
                                    "Array".to_string(),
                                ))
                            }
                        };
                        let unprotected = vals[1].clone();
                        let payload: Corim = match &vals[2] {
                            Value::Bytes(ref b) => ciborium::from_reader(&b[..])
                                .map_err(|e| Error::Deserialize(format!("corim {:?}", e)))?,
                            _ => {
                                return Err(Error::WrongValue(
                                    "SignedCorim payload".to_string(),
                                    "Bytes".to_string(),
                                ))
                            }
                        };
                        let signature: Vec<u8> = match &vals[3] {
                            Value::Bytes(b) => b.to_vec(),
                            _ => {
                                return Err(Error::WrongValue(
                                    "SignedCorim signature".to_string(),
                                    "Bytes".to_string(),
                                ))
                            }
                        };
                        Ok(SignedCorim {
                            protected,
                            unprotected,
                            payload,
                            signature,
                        })
                    }
                    _ => Err(Error::WrongValue(
                        "SigneCorim".to_string(),
                        "Array".to_string(),
                    )),
                }
            }
            _ => Err(Error::WrongValue(
                "SignedCorim".to_string(),
                "Tag".to_string(),
            )),
        }
    }
}

fn _pretty_print(v: Value, level: usize) -> String {
    use std::fmt::Write;
    let mut space = String::new();
    for _ in 0..level {
        write!(&mut space, " ").unwrap();
    }
    let mut out = String::new();
    match v {
        Value::Integer(i) => write!(&mut out, "Integer {:?}", i).unwrap(),
        Value::Bytes(_b) => write!(&mut out, "Bytes").unwrap(),
        Value::Float(f) => write!(&mut out, "Float {}", f).unwrap(),
        Value::Text(ss) => write!(&mut out, "\"{}\"", ss).unwrap(),
        Value::Bool(b) => write!(&mut out, "{}", b).unwrap(),
        Value::Null => write!(&mut out, "()").unwrap(),
        Value::Tag(t, v) => write!(
            &mut out,
            "T({}) {}",
            t,
            _pretty_print(*v.clone(), level + 1)
        )
        .unwrap(),
        Value::Array(vals) => {
            writeln!(&mut out, "ARRAY [").unwrap();
            for v in vals {
                writeln!(&mut out, "{}{}", space, _pretty_print(v.clone(), level + 1)).unwrap();
            }
            writeln!(&mut out, "{}]", space).unwrap()
        }
        Value::Map(vals) => {
            writeln!(&mut out, "MAP[").unwrap();
            for (t, v) in vals {
                writeln!(
                    &mut out,
                    "{}{} => {}",
                    space,
                    _pretty_print(t, level + 1),
                    _pretty_print(v, level + 1)
                )
                .unwrap();
            }
            writeln!(&mut out, "{}]", space).unwrap()
        }
        _ => todo!(),
    }
    out
}

pub fn pretty_print(v: Value) -> String {
    _pretty_print(v, 0)
}
