use num_bigint::{BigInt, Sign};
use num_traits::identities::Zero;

// See https://link.springer.com/content/pdf/10.1007%2F11745853_14.pdf

const DOUBLE_CONST: i32 = 121665; // This is (A - 2) / 4 in the paper

fn prime() -> BigInt{
    BigInt::parse_bytes(b"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed", 16).unwrap()
}

fn base_point() -> Vec<u8> {
    let mut result: Vec<u8> = vec![0;32];
    result[0] = 0x9;
    return result;
}

fn correct_mod(num: &BigInt) -> BigInt {
    // Handle the non-signed mod from the bigint package
    let prime = prime();
    if num.sign() == Sign::Minus {
        let neg_rem = num % &prime;
        if neg_rem.is_zero() {
            return neg_rem;
        }
        let result = neg_rem + &prime;
        return result;
    } else {
        return num % &prime;
    }
}

/// This requires that the base is equal to rhs - lhs
fn pseudo_add(lhs: &ProjectivePoint, rhs: &ProjectivePoint, base: &Point) -> ProjectivePoint {
    let point_diff = &lhs.x - &lhs.z;
    let point_sum = &lhs.x + &lhs.z;
    let prime_diff = &rhs.x - &rhs.z;
    let prime_sum = &rhs.x + &rhs.z;
    let left_product = point_diff * prime_sum;
    let right_product = point_sum * prime_diff;
    let x_square_base = &left_product + &right_product;
    let z_square_base = &left_product - &right_product;
    let xnew = correct_mod(&(&x_square_base * &x_square_base * 1));
    let znew = correct_mod(&(&z_square_base * &z_square_base * &base.x));
    ProjectivePoint {
        x: xnew,
        z: znew,
    }
}

fn pseudo_double( point: &ProjectivePoint) -> ProjectivePoint {
    let xplusz = (&point.x + &point.z);
    let xminusz = (&point.x - &point.z);
    let xplusz_squared = &xplusz * &xplusz;
    let xminusz_squared = &xminusz * &xminusz;
    let squared_diff = &xplusz_squared - &xminusz_squared;
    let xnew = correct_mod(&(&xplusz_squared * &xminusz_squared));
    let znew = correct_mod(&(&squared_diff * (&xplusz_squared + DOUBLE_CONST * &squared_diff)));
    ProjectivePoint {
        x: xnew,
        z: znew,
    }
}

pub fn multiply(value: &BigInt, point: &Point) -> Point {
    let (sign, bytes) = value.to_bytes_be();
    let mut point0 = ProjectivePoint::zero();
    let mut point1 = ProjectivePoint::from_point(&point);
    for byte in bytes {
        for i in 0..8 {
            if ((1 << (7 - i)) & byte) == 0 {
                let next0 = pseudo_double(&point0);
                let next1 = pseudo_add(&point0, &point1, point);
                point0 = next0;
                point1 = next1;
            } else {
                let next0 = pseudo_add(&point0, &point1, point);
                let next1 = pseudo_double(&point1);
                point0 = next0;
                point1 = next1;
            }
        }
    }
    return point0.normalize_to_point();
}

#[derive(PartialEq, Debug, Clone)]
pub struct Point {
    pub x: BigInt,
}

#[derive(PartialEq, Debug, Clone)]
pub struct ProjectivePoint {
    pub x: BigInt,
    pub z: BigInt,
}

impl ProjectivePoint {
    fn zero() -> ProjectivePoint {
        ProjectivePoint {
            x: BigInt::from(1),
            z: BigInt::from(0),
        }
    }

    fn from_point(point: &Point) -> ProjectivePoint {
        ProjectivePoint {
            x: point.x.clone(),
            z: BigInt::from(1),
        }
    }

    fn normalize_to_point(&self) -> Point {
        let zinverse = multiplicative_inverse(&self.z);
        Point {
            x: correct_mod(&(&self.x * zinverse)),
        }
    }
}

impl Point {
    fn zero() -> Point {
        Point {
            x: BigInt::from(0),
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        let x = correct_mod(&self.x);
        let (x_sign, mut x_bytes) = x.to_bytes_le();
        for i in 0..(32-x_bytes.len()) {
            x_bytes.push(0x00);
        }
        return x_bytes;
    }
    
    fn try_from_bytes(bytes: &[u8]) -> Option<Point> {
        if bytes.len() != 32 {
            return None;
        }

        let mut masked_bytes = bytes.to_vec();
        masked_bytes[31] &= 0x7f;
        
        return Some(Point {
            x: correct_mod(&BigInt::from_bytes_le(Sign::Plus, &masked_bytes)),
        });
    }
}

fn multiplicative_inverse(n: &BigInt) -> BigInt {
    let mut r = prime();
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
        t += prime();
    }
    return t;
}

pub fn curve25519(secret: &[u8], basepoint: &[u8]) -> Vec<u8>{
    assert_eq!(secret.len(), 32);
    assert_eq!(basepoint.len(), 32);
    let p = Point::try_from_bytes(basepoint).unwrap();

    let mut masked_bytes = secret.to_vec();
    masked_bytes[0] &= 248;
    masked_bytes[31] &= 127;
    masked_bytes[31] |= 64;
    let multiplier = BigInt::from_bytes_le(Sign::Plus, &masked_bytes);
    multiply(&multiplier, &p).to_bytes()
}

pub fn curve25519_base() -> Vec<u8> {
    base_point()
}

#[cfg(test)]
mod tests {
    use num_bigint::{BigInt};
    use super::{multiplicative_inverse, Point, curve25519};


    fn do_interations(num: usize) -> Vec<u8> {
        let initial = super::base_point();
        let mut k = initial.clone();
        let mut u = initial.clone();
        for _ in 0..num {
            let old_k = k.clone();
            k = curve25519(&k, &u);
            //println!("{} {} {}", hex::encode(&old_k), hex::encode(&u), hex::encode(&k));
            u = old_k.clone();
        }
        return k;
    }

    #[test]
    fn test_iteration() {
        let expected_bytes = hex::decode("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079").unwrap();
        let result = do_interations(1);
        assert_eq!(expected_bytes, result);
    }

    #[test]
    #[ignore]
    fn test_one_thousand() {
        let expected_bytes = hex::decode("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51").unwrap();
        let result = do_interations(1000);
        assert_eq!(expected_bytes, result);
    }

    #[test]
    fn test_vec1() {
        let scalar = hex::decode("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4").unwrap();
        let point = hex::decode("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c").unwrap();
        let result = curve25519(&scalar, &point);
        let expected_bytes = hex::decode("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552").unwrap();
        assert_eq!(expected_bytes, result);
    }

    #[test]
    fn test_vec2() {
        let scalar = hex::decode("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d").unwrap();
        let point = hex::decode("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493").unwrap();
        let result = curve25519(&scalar, &point);
        let expected_bytes = hex::decode("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957").unwrap();
        assert_eq!(expected_bytes, result);
    }
}