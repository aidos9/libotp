// EXAMPLE 01: An example of generating a 2FA code using the HOTP algorithm
extern crate lotp;
use lotp::hotp;

fn main() {
    // This secret shoudl be received from the server.
    let secret = String::from("PIYHMY3GOB4W44DJN54GGNLROA4WQMBTGVTTGZ3MOFZDA23MOU4WK6TJNVYTG3DUGZUGUMLZN5VDQMTBPF4XQNLBMZQWYND2NJRTA3BZNJYXK3LTMFUWY33QNVWXE33NPA2WSZTBOFXXK5JWPBXTG4DMOQ3GQY3HNRYWGMBVONQW45RVGI2WG6RSMU2HUMDPOY3HS2DUMJ5GW"); // Base-32 string
    for i in 0..10 {
        // Generate a 6 digit HOTP code, from the secret and the counter.
        match hotp::generate_6_digit_hotp_string(&i, &secret) {
            Ok(s) => println!("{}", s), // Successfully generated the code print it.
            Err(e) => println!("An error occurred: {}", e.description()), // An error occurred when generating the code, the ErrorType enum contains the possible error types.
        }
    }
}
