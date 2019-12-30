use crate::error::{Error, ErrorType};
use crate::hotp;
use std::time::{SystemTime, UNIX_EPOCH};

// Check a TOTP code with 6 digits as a string.
// secret - The secret used to generate the hash.
// offset - The amount of codes in the future and past that are to be allowed(Recommended to be 1).
// comparison - The code that is is to bee checked if valid.
// duration_secs - The amount of time before a new code should be generated.
pub fn check_6_digit_totp(
    secret: &String,
    offset: &u16,
    comparison: &String,
    duration_secs: &u64,
) -> Result<bool, Error> {
    let counter;

    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(c) => counter = c.as_secs() / duration_secs,
        Err(_) => {
            return Err(Error::new(
                ErrorType::InvalidCounter,
                "Could not calculate a value for the current counter.",
            ))
        }
    }

    if offset == &0u16 {
        return hotp::check_6_digit_hotp(&counter, secret, &(*offset as u64), comparison);
    }

    match duration_secs.checked_mul(*offset as u64) {
        Some(ref n) => return hotp::check_6_digit_hotp(&counter, secret, n, comparison),
        None => {
            return Err(Error::new(
                ErrorType::InvalidOffset,
                "Either the duration provdided or the offset specified is too large.",
            ))
        }
    }
}

// Check a TOTP code with 7 digits as a string.
// secret - The secret used to generate the hash.
// offset - The amount of codes in the future and past that are to be allowed(Recommended to be 1).
// comparison - The code that is is to bee checked if valid.
// duration_secs - The amount of time before a new code should be generated.
pub fn check_7_digit_totp(
    secret: &String,
    offset: &u16,
    comparison: &String,
    duration_secs: &u64,
) -> Result<bool, Error> {
    let counter;

    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(c) => counter = c.as_secs() / duration_secs,
        Err(_) => {
            return Err(Error::new(
                ErrorType::InvalidCounter,
                "Could not calculate a value for the current counter.",
            ))
        }
    }

    if offset == &0u16 {
        return hotp::check_7_digit_hotp(&counter, secret, &(*offset as u64), comparison);
    }

    match duration_secs.checked_mul(*offset as u64) {
        Some(ref n) => return hotp::check_6_digit_hotp(&counter, secret, n, comparison),
        None => {
            return Err(Error::new(
                ErrorType::InvalidOffset,
                "Either the duration provdided or the offset specified is too large.",
            ))
        }
    }
}

// Check a TOTP code with 8 digits as a string.
// secret - The secret used to generate the hash.
// offset - The amount of codes in the future and past that are to be allowed(Recommended to be 1).
// comparison - The code that is is to bee checked if valid.
// duration_secs - The amount of time before a new code should be generated.
pub fn check_8_digit_totp(
    secret: &String,
    offset: &u16,
    comparison: &String,
    duration_secs: &u64,
) -> Result<bool, Error> {
    let counter;

    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(c) => counter = c.as_secs() / duration_secs,
        Err(_) => {
            return Err(Error::new(
                ErrorType::InvalidCounter,
                "Could not calculate a value for the current counter.",
            ))
        }
    }

    if offset == &0u16 {
        return hotp::check_8_digit_hotp(&counter, secret, &(*offset as u64), comparison);
    }

    match duration_secs.checked_mul(*offset as u64) {
        Some(ref n) => return hotp::check_6_digit_hotp(&counter, secret, n, comparison),
        None => {
            return Err(Error::new(
                ErrorType::InvalidOffset,
                "Either the duration provdided or the offset specified is too large.",
            ))
        }
    }
}

// Generate a 6 digit TOTP code using the time since the UNIX epoch.
// secret - The secret used to generate the hash in base-32.
// duration_secs - The amount of seconds that the code should be valid for.
pub fn generate_6_digit_totp(secret: &String, duration_secs: &u64) -> Result<u64, Error> {
    let counter;

    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(c) => counter = c.as_secs() / duration_secs,
        Err(_) => {
            return Err(Error::new(
                ErrorType::InvalidCounter,
                "Could not calculate a value for the current counter.",
            ))
        }
    }

    return hotp::generate_6_digit_hotp(&counter, secret);
}

// Generate a 7 digit TOTP code using the time since the UNIX epoch.
// secret - The secret used to generate the hash in base-32.
// duration_secs - The amount of seconds that the code should be valid for.
pub fn generate_7_digit_totp(secret: &String, duration_secs: &u64) -> Result<u64, Error> {
    let counter;

    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(c) => counter = c.as_secs() / duration_secs,
        Err(_) => {
            return Err(Error::new(
                ErrorType::InvalidCounter,
                "Could not calculate a value for the current counter.",
            ))
        }
    }

    return hotp::generate_7_digit_hotp(&counter, secret);
}

// Generate a 8 digit TOTP code using the time since the UNIX epoch.
// secret - The secret used to generate the hash in base-32.
// duration_secs - The amount of seconds that the code should be valid for.
pub fn generate_8_digit_totp(secret: &String, duration_secs: &u64) -> Result<u64, Error> {
    let counter;

    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(c) => counter = c.as_secs() / duration_secs,
        Err(_) => {
            return Err(Error::new(
                ErrorType::InvalidCounter,
                "Could not calculate a value for the current counter.",
            ))
        }
    }

    return hotp::generate_8_digit_hotp(&counter, secret);
}

// Generate a 6 digit TOTP code using the time since the UNIX epoch. Returns a string instead of a number
// secret - The secret used to generate the hash in base-32.
// duration_secs - The amount of seconds that the code should be valid for.
pub fn generate_6_digit_totp_string(secret: &String, duration_secs: &u64) -> Result<String, Error> {
    match generate_6_digit_totp(secret, duration_secs) {
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

// Generate a 7 digit TOTP code using the time since the UNIX epoch. Returns a string instead of a number
// secret - The secret used to generate the hash in base-32.
// duration_secs - The amount of seconds that the code should be valid for.
pub fn generate_7_digit_totp_string(secret: &String, duration_secs: &u64) -> Result<String, Error> {
    match generate_7_digit_totp(secret, duration_secs) {
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

// Generate a 8 digit TOTP code using the time since the UNIX epoch. Returns a string instead of a number
// secret - The secret used to generate the hash in base-32.
// duration_secs - The amount of seconds that the code should be valid for.
pub fn generate_8_digit_totp_string(secret: &String, duration_secs: &u64) -> Result<String, Error> {
    match generate_8_digit_totp(secret, duration_secs) {
        Ok(n) => {
            let mut string: String = format!("{}", n);
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
    fn test_generate_6_digit_totp() {
        use super::*;
        match generate_6_digit_totp(&String::from("abcdef234567abcdef234567"), &30) {
            Ok(_) => (),
            Err(e) => panic!(
                "An error occurred when generating the hotp: {}",
                e.description()
            ),
        }
    }

    #[test]
    fn test_generate_7_digit_totp() {
        use super::*;
        match generate_7_digit_totp(&String::from("abcdef234567abcdef234567"), &30) {
            Ok(_) => (),
            Err(e) => panic!(
                "An error occurred when generating the hotp: {}",
                e.description()
            ),
        }
    }

    #[test]
    fn test_generate_8_digit_totp() {
        use super::*;
        match generate_8_digit_totp(&String::from("abcdef234567abcdef234567"), &30) {
            Ok(_) => (),
            Err(e) => panic!(
                "An error occurred when generating the hotp: {}",
                e.description()
            ),
        }
    }

    #[test]
    fn test_generate_6_digit_totp_string() {
        use super::*;
        match generate_6_digit_totp_string(&String::from("abcdef234567abcdef234567"), &30) {
            Ok(c) => assert_eq!(c.len(), 6),
            Err(e) => panic!(
                "An error occurred when generating the hotp: {}",
                e.description()
            ),
        }
    }

    #[test]
    fn test_generate_7_digit_totp_string() {
        use super::*;
        match generate_7_digit_totp_string(&String::from("abcdef234567abcdef234567"), &30) {
            Ok(c) => assert_eq!(c.len(), 7),
            Err(e) => panic!(
                "An error occurred when generating the hotp: {}",
                e.description()
            ),
        }
    }

    #[test]
    fn test_generate_8_digit_totp_string() {
        use super::*;
        match generate_8_digit_totp_string(&String::from("abcdef234567abcdef234567"), &30) {
            Ok(c) => assert_eq!(c.len(), 8),
            Err(e) => panic!(
                "An error occurred when generating the hotp: {}",
                e.description()
            ),
        }
    }
}
