// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use ciborium::Value;
use corim_experiments::VersionMap;
use corim_experiments::WrappedDigests;
use corim_experiments::pretty_print;
use corim_experiments::FlagsMap;
use corim_experiments::TypeChoice;
use corim_experiments::CorimBuilder;

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

#[test]
fn test_version_map() {
    use ciborium::cbor;

    let map = ciborium::cbor!( {
        0 => "0.0.0",
        1 => 3,

    })
    .unwrap();

    let _: VersionMap = map.deserialized().unwrap();

    let sample = VersionMap::new("0.0.0".to_string(), 3);

    let serialized = Value::serialized(&sample).unwrap();

    assert!(serialized == map);
}

#[test]
fn type_choice_tests() {
    let int_value = ciborium::cbor!(1234).unwrap();

    let text_value = ciborium::cbor!("this is text").unwrap();

    let uid_value = Value::Tag(37, Box::new(Value::Bytes(vec![0, 1, 2, 3, 4])));

    let result: TypeChoice = match int_value.deserialized() {
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

#[test]
fn corim_builder_tests() {
    let builder = CorimBuilder::new();

    let result = builder.build();

    assert!(result.is_err());

    let mut builder = CorimBuilder::new();

    builder.vendor("foo".to_string());
    builder.id("baz".to_string());
    builder.tag_id("quux".to_string());
    builder.add_hash("layer1".to_string(), 10, vec![0; 32]);

    let result = builder.build();

    assert!(result.is_ok());
}
