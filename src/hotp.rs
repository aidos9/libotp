use crate::error::{Error, ErrorType};
use ring::hmac;

// Check a HOTP code with 6 digits as a string.
// counter - the value of the hotp counter.
// secret - The secret used to generate the hash.
// offset - The value added and subtracted from the counter that are considered valid.
// comparison - The code that is is to bee checked if valid.
pub fn check_6_digit_hotp(
    counter: &u64,
    secret: &String,
    offset: &u64,
    comparison: &String,
) -> Result<bool, Error> {
    if offset == &0u64 {
        match generate_6_digit_hotp_string(counter, secret) {
            Ok(ref hotp) => return Ok(hotp == comparison),
            Err(e) => return Err(e),
        }
    } else {
        let min;
        let max;

        match counter.checked_sub(*offset) {
            Some(m) => min = m,
            None => min = 0,
        }

        match counter.checked_add(*offset) {
            Some(m) => max = m,
            None => max = std::u64::MAX,
        }

        for i in min..=max {
            match generate_6_digit_hotp_string(&i, secret) {
                Ok(ref hotp) => {
                    if hotp == comparison {
                        return Ok(true);
                    }
                }
                Err(e) => return Err(e),
            }
        }
    }

    return Ok(false);
}

// Check a HOTP code with 7 digits as a string.
// counter - the value of the hotp counter.
// secret - The secret used to generate the hash.
// offset - The value added and subtracted from the counter that are considered valid.
// comparison - The code that is is to bee checked if valid.
pub fn check_7_digit_hotp(
    counter: &u64,
    secret: &String,
    offset: &u64,
    comparison: &String,
) -> Result<bool, Error> {
    if offset == &0u64 {
        match generate_7_digit_hotp_string(counter, secret) {
            Ok(ref hotp) => return Ok(hotp == comparison),
            Err(e) => return Err(e),
        }
    } else {
        let min;
        let max;

        match counter.checked_sub(*offset) {
            Some(m) => min = m,
            None => min = 0,
        }

        match counter.checked_add(*offset) {
            Some(m) => max = m,
            None => max = std::u64::MAX,
        }

        for i in min..=max {
            match generate_7_digit_hotp_string(&i, secret) {
                Ok(ref hotp) => {
                    if hotp == comparison {
                        return Ok(true);
                    }
                }
                Err(e) => return Err(e),
            }
        }
    }

    return Ok(false);
}

// Check a HOTP code with 8 digits as a string.
// counter - the value of the hotp counter.
// secret - The secret used to generate the hash.
// offset - The value added and subtracted from the counter that are considered valid.
// comparison - The code that is is to bee checked if valid.
pub fn check_8_digit_hotp(
    counter: &u64,
    secret: &String,
    offset: &u64,
    comparison: &String,
) -> Result<bool, Error> {
    if offset == &0u64 {
        match generate_8_digit_hotp_string(counter, secret) {
            Ok(ref hotp) => return Ok(hotp == comparison),
            Err(e) => return Err(e),
        }
    } else {
        let min;
        let max;

        match counter.checked_sub(*offset) {
            Some(m) => min = m,
            None => min = 0,
        }

        match counter.checked_add(*offset) {
            Some(m) => max = m,
            None => max = std::u64::MAX,
        }

        for i in min..=max {
            match generate_8_digit_hotp_string(&i, secret) {
                Ok(ref hotp) => {
                    if hotp == comparison {
                        return Ok(true);
                    }
                }
                Err(e) => return Err(e),
            }
        }
    }

    return Ok(false);
}

// Generate a HOTP code with 6 digits as a number.
// counter - the value of the hotp counter.
// secret - The secret used to generate the hash.
pub fn generate_6_digit_hotp(counter: &u64, secret: &String) -> Result<u64, Error> {
    let bytes;
    match base32::decode(base32::Alphabet::RFC4648 { padding: false }, &secret) {
        Some(b) => bytes = b,
        None => {
            return Err(Error::new(
                ErrorType::NonBase32,
                "The secret provided is not a base-32 string.",
            ))
        }
    }

    let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, &bytes);

    let tag = hmac::sign(&key, &counter.to_be_bytes().to_vec());
    let offset = tag.as_ref()[19] & 0xf;
    let bin_code = ((tag.as_ref()[offset as usize] & 0x7f) as i32) << 24
        | ((tag.as_ref()[(offset as usize) + 1] & 0xff) as i32) << 16
        | ((tag.as_ref()[(offset as usize) + 2] & 0xff) as i32) << 8
        | ((tag.as_ref()[(offset as usize) + 3] as i32) & 0xff);

    return Ok(bin_code as u64 % 1000000);
}

// Generate a HOTP code with 7 digits as a number.
pub fn generate_7_digit_hotp(counter: &u64, secret: &String) -> Result<u64, Error> {
    let bytes;
    match base32::decode(base32::Alphabet::RFC4648 { padding: false }, &secret) {
        Some(b) => bytes = b,
        None => {
            return Err(Error::new(
                ErrorType::NonBase32,
                "The secret provided is not a base-32 string.",
            ))
        }
    }

    let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, &bytes);

    let tag = hmac::sign(&key, &counter.to_be_bytes().to_vec());
    let offset = tag.as_ref()[19] & 0xf;
    let bin_code = ((tag.as_ref()[offset as usize] & 0x7f) as i32) << 24
        | ((tag.as_ref()[(offset as usize) + 1] & 0xff) as i32) << 16
        | ((tag.as_ref()[(offset as usize) + 2] & 0xff) as i32) << 8
        | ((tag.as_ref()[(offset as usize) + 3] as i32) & 0xff);

    return Ok(bin_code as u64 % 10000000);
}

// Generate a HOTP code with 8 digits as a number.
pub fn generate_8_digit_hotp(counter: &u64, secret: &String) -> Result<u64, Error> {
    let bytes;
    match base32::decode(base32::Alphabet::RFC4648 { padding: false }, &secret) {
        Some(b) => bytes = b,
        None => {
            return Err(Error::new(
                ErrorType::NonBase32,
                "The secret provided is not a base-32 string.",
            ))
        }
    }

    let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, &bytes);

    let tag = hmac::sign(&key, &counter.to_be_bytes().to_vec());
    let offset = tag.as_ref()[19] & 0xf;
    let bin_code = ((tag.as_ref()[offset as usize] & 0x7f) as i32) << 24
        | ((tag.as_ref()[(offset as usize) + 1] & 0xff) as i32) << 16
        | ((tag.as_ref()[(offset as usize) + 2] & 0xff) as i32) << 8
        | ((tag.as_ref()[(offset as usize) + 3] as i32) & 0xff);

    return Ok(bin_code as u64 % 100000000);
}

// Generate a HOTP code with 6 digits as a string.
pub fn generate_6_digit_hotp_string(counter: &u64, secret: &String) -> Result<String, Error> {
    match generate_6_digit_hotp(counter, secret) {
        Ok(n) => {
            let mut string: String = format!("{}", n);
            while string.len() < 6 {
                string.insert(0, '0');
            }

            return Ok(string);
        }
        Err(e) => return Err(e),
    }
}

// Generate a HOTP code with 7 digits as a string.
pub fn generate_7_digit_hotp_string(counter: &u64, secret: &String) -> Result<String, Error> {
    match generate_7_digit_hotp(counter, secret) {
        Ok(n) => {
            let mut string: String = format!("{}", n);
            while string.len() < 7 {
                string.insert(0, '0');
            }

            return Ok(string);
        }
        Err(e) => return Err(e),
    }
}

// Generate a HOTP code with 8 digits as a string.
pub fn generate_8_digit_hotp_string(counter: &u64, secret: &String) -> Result<String, Error> {
    match generate_8_digit_hotp(counter, secret) {
        Ok(n) => {
            let mut string: String = format!("{}", n);
            // Prepend with zeroes until we reach a length of 8.
            while string.len() < 8 {
                string.insert(0, '0');
            }

            return Ok(string);
        }
        Err(e) => return Err(e),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_generate_6_digit_hotp() {
        use super::*;
        match generate_6_digit_hotp(&0, &String::from("abcdef234567")) {
            Ok(_) => (),
            Err(e) => panic!(
                "An error occurred when generating the hotp: {}",
                e.description()
            ),
        }
    }

    #[test]
    fn test_generate_7_digit_hotp() {
        use super::*;
        match generate_7_digit_hotp(&0, &String::from("abcdef234567")) {
            Ok(_) => (),
            Err(e) => panic!(
                "An error occurred when generating the hotp: {}",
                e.description()
            ),
        }
    }

    #[test]
    fn test_generate_8_digit_hotp() {
        use super::*;
        match generate_8_digit_hotp(&0, &String::from("abcdef234567")) {
            Ok(_) => (),
            Err(e) => panic!(
                "An error occurred when generating the hotp: {}",
                e.description()
            ),
        }
    }

    #[test]
    fn test_generate_6_digit_hotp_string() {
        use super::*;
        match generate_6_digit_hotp_string(&0, &String::from("abcdef234567")) {
            Ok(s) => assert_eq!(s.len(), 6),
            Err(e) => panic!(
                "An error occurred when generating the hotp: {}",
                e.description()
            ),
        }
    }

    #[test]
    fn test_generate_7_digit_hotp_string() {
        use super::*;
        match generate_7_digit_hotp_string(&0, &String::from("abcdef234567")) {
            Ok(s) => assert_eq!(s.len(), 7),
            Err(e) => panic!(
                "An error occurred when generating the hotp: {}",
                e.description()
            ),
        }
    }

    #[test]
    fn test_generate_8_digit_hotp_string() {
        use super::*;
        match generate_8_digit_hotp_string(&0, &String::from("abcdef234567")) {
            Ok(s) => assert_eq!(s.len(), 8),
            Err(e) => panic!(
                "An error occurred when generating the hotp: {}",
                e.description()
            ),
        }
    }

    #[test]
    fn test_check_6_digit_hotp_success() {
        use super::*;
        match generate_6_digit_hotp_string(&400u64, &String::from("abcdef234567")) {
            Ok(ref s) => {
                match check_6_digit_hotp(&397u64, &String::from("abcdef234567"), &6u64, s) {
                    Ok(b) => assert!(b),
                    Err(e) => panic!(
                        "An error occurred when generating the hotp: {}",
                        e.description()
                    ),
                }
            }
            Err(e) => panic!(
                "An error occurred when checking the hotp: {}",
                e.description()
            ),
        }
    }

    #[test]
    fn test_check_6_digit_hotp_fail() {
        use super::*;
        match generate_6_digit_hotp_string(&400u64, &String::from("abcdef234567")) {
            Ok(ref s) => {
                match check_6_digit_hotp(&397u64, &String::from("abcdef234567"), &1u64, s) {
                    Ok(b) => assert!(!b),
                    Err(e) => panic!(
                        "An error occurred when checking the hotp: {}",
                        e.description()
                    ),
                }
            }
            Err(e) => panic!(
                "An error occurred when generating the hotp: {}",
                e.description()
            ),
        }
    }

    #[test]
    fn test_check_7_digit_hotp_success() {
        use super::*;
        match generate_7_digit_hotp_string(&400u64, &String::from("abcdef234567")) {
            Ok(ref s) => {
                match check_7_digit_hotp(&397u64, &String::from("abcdef234567"), &6u64, s) {
                    Ok(b) => assert!(b),
                    Err(e) => panic!(
                        "An error occurred when generating the hotp: {}",
                        e.description()
                    ),
                }
            }
            Err(e) => panic!(
                "An error occurred when checking the hotp: {}",
                e.description()
            ),
        }
    }

    #[test]
    fn test_check_7_digit_hotp_fail() {
        use super::*;
        match generate_7_digit_hotp_string(&400u64, &String::from("abcdef234567")) {
            Ok(ref s) => {
                match check_7_digit_hotp(&397u64, &String::from("abcdef234567"), &1u64, s) {
                    Ok(b) => assert!(!b),
                    Err(e) => panic!(
                        "An error occurred when checking the hotp: {}",
                        e.description()
                    ),
                }
            }
            Err(e) => panic!(
                "An error occurred when generating the hotp: {}",
                e.description()
            ),
        }
    }

    #[test]
    fn test_check_8_digit_hotp_success() {
        use super::*;
        match generate_8_digit_hotp_string(&400u64, &String::from("abcdef234567")) {
            Ok(ref s) => {
                match check_8_digit_hotp(&397u64, &String::from("abcdef234567"), &6u64, s) {
                    Ok(b) => assert!(b),
                    Err(e) => panic!(
                        "An error occurred when generating the hotp: {}",
                        e.description()
                    ),
                }
            }
            Err(e) => panic!(
                "An error occurred when checking the hotp: {}",
                e.description()
            ),
        }
    }

    #[test]
    fn test_check_8_digit_hotp_fail() {
        use super::*;
        match generate_8_digit_hotp_string(&400u64, &String::from("abcdef234567")) {
            Ok(ref s) => {
                match check_8_digit_hotp(&397u64, &String::from("abcdef234567"), &1u64, s) {
                    Ok(b) => assert!(!b),
                    Err(e) => panic!(
                        "An error occurred when checking the hotp: {}",
                        e.description()
                    ),
                }
            }
            Err(e) => panic!(
                "An error occurred when generating the hotp: {}",
                e.description()
            ),
        }
    }
}
