use num_bigint::{BigInt, Sign};
use num_bigint::ToBigInt;

#[derive(PartialEq, Debug)]
pub struct ElipticCurve {
    pub p: BigInt,
    pub a: BigInt,
    pub b: BigInt,
    pub g: Point,
    pub n: BigInt,
    pub bytes: usize,
}

fn correct_mod(num: &BigInt, p: &BigInt) -> BigInt {
    // Handle the non-signed mod from the bigint package
    if num.sign() == Sign::Minus {
        let neg_rem = num % p;
        let result = neg_rem + p;
        return result;
    } else {
        return num % p;
    }
}

impl ElipticCurve {
    fn add(&self, lhs: &Point, rhs: &Point) -> Point {
        if lhs.zero {
            return rhs.clone();
        } else if rhs.zero {
            return lhs.clone();
        } else if lhs.x == rhs.x {
            if lhs.y == rhs.y {
                return self.double(lhs);
            } else {
                return Point {
                    zero: true,
                    x: BigInt::from(0),
                    y: BigInt::from(0)
                }
            }
        }
        let x_diff = correct_mod(&(&rhs.x - &lhs.x), &self.p);
        let y_diff = correct_mod(&(&rhs.y - &lhs.y), &self.p);
        let x_diff_inverse = multiplicative_inverse(&x_diff, &self.p);
        let lambda = y_diff * x_diff_inverse;
        let result_x = correct_mod(&(&lambda * &lambda - &rhs.x - &lhs.x), &self.p);
        let result_y = correct_mod(&(&lambda * (&lhs.x - &result_x) - &lhs.y), &self.p);
        Point {
            zero: false,
            x: result_x,
            y: result_y,
        }
    }

    fn double(&self, point: &Point) -> Point {
        if point.zero {
            return point.clone();
        }
        let numerator = 3 * (&point.x * &point.x) + &self.a;
        let denominator = 2 * &point.y;
        let denominator_inverse = multiplicative_inverse(&denominator, &self.p);

        let lambda = numerator * denominator_inverse;
        let result_x = correct_mod(&(&lambda * &lambda - 2 * &point.x), &self.p);

        let result_y: BigInt = correct_mod(&(&lambda * (&point.x - &result_x) - &point.y), &self.p);

        Point {
            zero: false,
            x: result_x,
            y: result_y
        }
    }

    pub fn multiply(&self, value: BigInt, point: &Point) -> Point {
        let (sign, bytes) = value.to_bytes_be();
        let mut current = Point::zero();
        for byte in bytes {
            for i in 0..8 {
                current = self.double(&current);
                if ((1 << (7 - i)) & byte) > 0 {
                    current = self.add(&current, &point);
                }
            }
        }
        return current;
    }

    pub fn secp256r1() -> ElipticCurve {
        ElipticCurve {
            p: BigInt::parse_bytes(b"FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16).unwrap(),
            a: BigInt::parse_bytes(b"FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC", 16).unwrap(),
            b: BigInt::parse_bytes(b"5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16).unwrap(),
            g: Point {
                zero: false,
                x: BigInt::parse_bytes(b"6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296", 16).unwrap(),
                y: BigInt::parse_bytes(b"4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5", 16).unwrap(),
            },
            n: BigInt::parse_bytes(b"FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16).unwrap(),
            bytes: 32,
        }
    }

    pub fn point_to_bytes(&self, p: &Point) -> Vec<u8> {
        let mut result: Vec<u8> = Vec::with_capacity(self.bytes * 2 + 1);
        result.push(0x04);
        let (x_sign, x_bytes) = p.x.to_bytes_be();
        for i in 0..(self.bytes - x_bytes.len()) {
            result.push(0x00);
        }
        result.extend(x_bytes);
        let (y_sign, y_bytes) = p.y.to_bytes_be();
        for i in 0..(self.bytes - y_bytes.len()) {
            result.push(0x00);
        }
        result.extend(y_bytes);
        return result;
    }

    pub fn try_point_from_bytes(&self, bytes: &[u8]) -> Option<Point> {
        if bytes.len() != self.bytes * 2 + 1 {
            return None;
        }
        if bytes[0] != 0x04 {
            return None;
        }
        let x_bytes = &bytes[1..(self.bytes + 1)];
        let y_bytes = &bytes[(self.bytes + 1)..(2 * self.bytes + 1)];
        let x = BigInt::from_bytes_be(Sign::Plus, x_bytes);
        let y = BigInt::from_bytes_be(Sign::Plus, y_bytes);
        let p = Point {
            zero: false,
            x: x,
            y: y
        };
        if !self.verify_on_curve(&p) {
            return None;
        }
        return Some(p);
    }

    pub fn verify_on_curve(&self, p: &Point) -> bool {
        let total_value = &p.y * &p.y - &p.x * &p.x * &p.x - &self.a * &p.x - &self.b;
        let mod_value = correct_mod(&total_value, &self.p);
        return mod_value == BigInt::from(0);
    }
}

#[derive(PartialEq, Debug, Clone)]
pub struct Point {
    pub zero: bool,
    pub x: BigInt,
    pub y: BigInt,
}

impl Point {
    fn zero() -> Point {
        Point {
            zero: true,
            x: BigInt::from(0),
            y: BigInt::from(0),
        }
    }
}

fn multiplicative_inverse(n: &BigInt, p: &BigInt) -> BigInt {
    let mut r = p.clone();
    let mut new_r = n.clone();
    let mut t = BigInt::from(0u32);
    let mut new_t = BigInt::from(1u32);
    while new_r != BigInt::from(0u32) {
        let quotient = &r / &new_r;
        let temp_t = new_t;
        new_t  = t - &quotient * &temp_t;
        t = temp_t;
        let temp_r = new_r;
        new_r = r - &quotient * &temp_r;
        r = temp_r;
    }
    if r > BigInt::from(1) {
        panic!("n is not invertable!");
    }
    if t < BigInt::from(0) {
        t += p.to_bigint().unwrap();
    }
    return t;
}

#[cfg(test)]
mod tests {
    use num_bigint::{BigInt};
    use super::{ElipticCurve, Point};

    #[test]
    fn test_inverse() {
        let inverse = super::multiplicative_inverse(&BigInt::from(3u32), &BigInt::from(19u32));
    }

    #[test]
    fn test_add() {
        let curve = ElipticCurve {
            p: BigInt::from(17),
            a: BigInt::from(1), 
            b: BigInt::from(0),
            g: Point {
                zero: false,
                x: BigInt::from(0),
                y: BigInt::from(0),
            },
            n: BigInt::from(5),
            bytes: 1,
        };
        let a = Point {
            zero: false,
            x: BigInt::from(3),
            y: BigInt::from(9),
        };
        let b = Point {
            zero: false,
            x: BigInt::from(6),
            y: BigInt::from(16),
        };
        let new_point = curve.add(&a, &b);
    }

    #[test]
    fn test_mul_small() {
        let curve = ElipticCurve {
            p: BigInt::parse_bytes(b"113", 10).unwrap(),
            a: BigInt::from(0), 
            b: BigInt::from(109),
            g: Point {
                zero: false,
                x: BigInt::parse_bytes(b"2", 10).unwrap(),
                y: BigInt::parse_bytes(b"2", 10).unwrap(),
            },
            n: BigInt::from(100),
            bytes: 1,
        };
        let expected_x = BigInt::parse_bytes(b"110", 10).unwrap();
        let expected_y = BigInt::parse_bytes(b"46", 10).unwrap();
        let new_point = curve.multiply(BigInt::from(11), &curve.g);
        assert_eq!(new_point.x, expected_x);
        assert_eq!(new_point.y, expected_y);
    }

    #[test]
    fn test_mul() {
        let curve = ElipticCurve {
            p: BigInt::parse_bytes(b"115792089237316195423570985008687907853269984665640564039457584007908834671663", 10).unwrap(),
            a: BigInt::from(0), 
            b: BigInt::from(7),
            g: Point {
                zero: false,
                x: BigInt::parse_bytes(b"55066263022277343669578718895168534326250603453777594175500187360389116729240", 10).unwrap(),
                y: BigInt::parse_bytes(b"32670510020758816978083085130507043184471273380659243275938904335757337482424", 10).unwrap(),
            },
            n: BigInt::from(100),
            bytes: 32,
        };
        let expected_x = BigInt::parse_bytes(b"53957576663012291606402345341061437133522758407718089353314528343643821967563", 10).unwrap();
        let expected_y = BigInt::parse_bytes(b"98386217607324929854432842186271083758341411730506808463586570492533445740059", 10).unwrap();
        let new_point = curve.multiply(BigInt::from(11), &curve.g);
        assert_eq!(new_point.x, expected_x);
        assert_eq!(new_point.y, expected_y);
    }
}