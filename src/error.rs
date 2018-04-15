use std::error::Error;
use std::fmt::{self, Display, Debug};
use ::data_types::Capability;
use ::response::Response;

#[derive(Debug)]
pub enum LogicError {
    /// The server replied with a error response code
    Code(Response),

    /// The server replied with a non-error response code, but the command could not handle it
    ///
    /// For example on DATA the server responds with the intermediate code 354, if the client
    /// now receives e.g. a 240 than clearly something went wrong.
    UnexpectedCode(Response),

    /// a custom error code
    ///
    /// This is meant to be produced by a custom command, as the sender of the command knows
    /// (at some abstraction level) which command it send, it can downcast and handle the
    /// error
    Custom(Box<Error + 'static + Send + Sync>)
}

pub fn check_response(response: Response) -> Result<Response, LogicError> {
    if response.is_erroneous() {
        Err(LogicError::Code(response))
    } else {
        Ok(response)
    }
}


impl Error for LogicError {

    fn description(&self) -> &str {
        use self::LogicError::*;
        match *self {
            Code(_) => "server responded with error response code",
            UnexpectedCode(_) => "server responded with unexpected non-error response code",
            Custom(ref boxed) => boxed.description()
        }
    }

    fn cause(&self) -> Option<&Error> {
        use self::LogicError::*;
        match *self {
            Custom(ref boxed) => boxed.cause(),
            _ => None
        }
    }
}

impl Display for LogicError {

    fn fmt(&self, fter: &mut fmt::Formatter) -> fmt::Result {
        use self::LogicError::*;

        match *self {
            Custom(ref boxed) => Display::fmt(boxed, fter),
            //FIXME better display impl
            _ => Debug::fmt(self, fter),
        }
    }
}


#[derive(Debug, Clone)]
pub struct MissingCapabilities {
    capabilities: Vec<Capability>
}

impl MissingCapabilities {

    pub fn new(capabilities: Vec<Capability>) -> Self {
        MissingCapabilities { capabilities }
    }

    pub fn capabilities(&self) -> &[Capability] {
        &self.capabilities
    }
}

impl Into<Vec<Capability>> for MissingCapabilities {
    fn into(self) -> Vec<Capability> {
        let MissingCapabilities { capabilities } = self;
        capabilities
    }
}

impl From<Vec<Capability>> for MissingCapabilities {
    fn from(capabilities: Vec<Capability>) -> Self {
        MissingCapabilities { capabilities }
    }
}

impl Error for MissingCapabilities {
    fn description(&self) -> &str {
        "missing capabilities to run command"
    }
}

impl Display for MissingCapabilities {

    fn fmt(&self, fter: &mut fmt::Formatter) -> fmt::Result {
        write!(fter, "missing capabilities:")?;
        let mut first = true;
        for cap in self.capabilities.iter() {
            let str_cap = cap.as_str();
            if first {
                write!(fter, " {}", str_cap)?;
            } else {
                write!(fter, ", {}", str_cap)?;
            }
            first = false;
        }
        Ok(())
    }
}