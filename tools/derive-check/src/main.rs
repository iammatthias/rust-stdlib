use rust_stdlib::encoding::json;
use rust_stdlib_derive::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct Metadata<T = String, const N: usize = 3> {
    name: T,
    ratings: [u8; N],
}

fn encode<T: json::Serialize + ?Sized>(value: &T) -> Result<String, json::Error> {
    Ok(String::from_utf8_lossy(&json::marshal(value)?).into_owned())
}
fn decode<T: json::Deserialize>(text: &str) -> Result<T, json::Error> {
    json::unmarshal(text.as_bytes())
}

fn main() -> Result<(), json::Error> {
    let metadata: Metadata = Metadata {
        name: "contact-sheet".into(),
        ratings: [3, 5, 1],
    };
    let encoded = encode(&metadata)?;
    let decoded: Metadata = decode(&encoded)?;
    assert_eq!(decoded, metadata);
    println!("{encoded}");
    Ok(())
}
