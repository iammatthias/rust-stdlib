use rust_stdlib::encoding::{
    BinaryAppender, BinaryMarshaler, BinaryUnmarshaler, TextAppender, TextMarshaler,
    TextUnmarshaler,
};
use std::error::Error;

#[derive(Debug, Default, PartialEq)]
struct Point {
    x: u8,
    y: u8,
}

impl TextMarshaler for Point {
    fn marshal_text(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        Ok(format!("{},{}", self.x, self.y).into_bytes())
    }
}

impl TextUnmarshaler for Point {
    fn unmarshal_text(&mut self, text: &[u8]) -> Result<(), Box<dyn Error>> {
        let text = std::str::from_utf8(text)?;
        let (x, y) = text.split_once(',').ok_or("missing comma")?;
        self.x = x.parse()?;
        self.y = y.parse()?;
        Ok(())
    }
}

impl TextAppender for Point {
    fn append_text(&self, out: &mut Vec<u8>) -> Result<(), Box<dyn Error>> {
        out.extend(self.marshal_text()?);
        Ok(())
    }
}

impl BinaryMarshaler for Point {
    fn marshal_binary(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        Ok(vec![self.x, self.y])
    }
}

impl BinaryUnmarshaler for Point {
    fn unmarshal_binary(&mut self, data: &[u8]) -> Result<(), Box<dyn Error>> {
        match data {
            [x, y] => {
                self.x = *x;
                self.y = *y;
                Ok(())
            }
            _ => Err("want two bytes".into()),
        }
    }
}

impl BinaryAppender for Point {
    fn append_binary(&self, out: &mut Vec<u8>) -> Result<(), Box<dyn Error>> {
        out.extend(self.marshal_binary()?);
        Ok(())
    }
}

#[test]
fn text_round_trip_and_append() {
    let mut p = Point::default();
    p.unmarshal_text(b"3,250").unwrap();
    assert_eq!(p, Point { x: 3, y: 250 });
    assert_eq!(p.marshal_text().unwrap(), b"3,250");
    let mut out = b"at:".to_vec();
    p.append_text(&mut out).unwrap();
    assert_eq!(out, b"at:3,250");
    assert!(p.unmarshal_text(b"300,1").is_err());
    assert!(p.unmarshal_text(b"nocomma").is_err());
}

#[test]
fn binary_round_trip_and_append() {
    let mut p = Point::default();
    p.unmarshal_binary(&[7, 9]).unwrap();
    assert_eq!(p.marshal_binary().unwrap(), vec![7, 9]);
    let mut out = vec![0xff];
    p.append_binary(&mut out).unwrap();
    assert_eq!(out, vec![0xff, 7, 9]);
    assert!(p.unmarshal_binary(&[1]).is_err());
}
