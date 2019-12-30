// EXAMPLE 02: An example of generating a 2FA code using the TOTP algorithm
extern crate lotp;
use lotp::totp;
use std::{thread, time};

fn main() {
    // This secret should be received from the server.
    let secret = String::from("PIYHMY3GOB4W44DJN54GGNLROA4WQMBTGVTTGZ3MOFZDA23MOU4WK6TJNVYTG3DUGZUGUMLZN5VDQMTBPF4XQNLBMZQWYND2NJRTA3BZNJYXK3LTMFUWY33QNVWXE33NPA2WSZTBOFXXK5JWPBXTG4DMOQ3GQY3HNRYWGMBVONQW45RVGI2WG6RSMU2HUMDPOY3HS2DUMJ5GW"); // Base-32 string
                                                                                                                                                                                                                                                // Generate 10 codes, there should be two different codes as we expect a different code after 10 seconds.
    for i in 0..=10 {
        // Generate a 6 digit TOTP code from the secret, for every 10 seconds.
        match totp::generate_6_digit_totp_string(&secret, &10) {
            Ok(s) => println!("{} ({})", s, i), // Successfully generated the code print it.
            Err(e) => println!("An error occurred: {}", e.description()), // An error occurred when generating the code, the ErrorType enum contains the possible error types.
        }

        thread::sleep(time::Duration::from_secs(1));
    }
}
