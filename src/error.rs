// Contains all the possible types of errors.
#[derive(Clone, PartialEq)]
pub enum ErrorType {
    NonBase32,      // The string supplied wasn't a base-32 string.
    InvalidCounter, // The counter was invalid when checking the unix time.
    InvalidOffset,  // The offset when checking tokens is too large or small.
}

// Struct which is returned to indicate an error.
#[derive(Clone, PartialEq)]
pub struct Error {
    err_type: ErrorType,
    desc: String,
}

impl Error {
    // Creates a new error.
    pub fn new(error_type: ErrorType, description: &'static str) -> Error {
        return Error {
            err_type: error_type,
            desc: String::from(description),
        };
    }

    // Returns the type of error that occurred.
    pub fn error_type(&self) -> ErrorType {
        return self.err_type.clone();
    }

    // Returns a description of the error that occurred.
    pub fn description(&self) -> String {
        return self.desc.clone();
    }
}
