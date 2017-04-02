use advapi32;
use std::io;
use std::ptr;
use winapi;

use Inner;

/// A CryptoAPI handle to a provider of a key.
pub struct CryptProv(winapi::HCRYPTPROV);

impl Drop for CryptProv {
    fn drop(&mut self) {
        unsafe {
            advapi32::CryptReleaseContext(self.0, 0);
        }
    }
}

impl Inner<winapi::HCRYPTPROV> for CryptProv {
    unsafe fn from_inner(t: winapi::HCRYPTPROV) -> Self {
        CryptProv(t)
    }

    fn as_inner(&self) -> winapi::HCRYPTPROV {
        self.0
    }

    fn get_mut(&mut self) -> &mut winapi::HCRYPTPROV {
        &mut self.0
    }
}

impl CryptProv {
    /// Returns a provider configured for use when the private key does not need
    /// to be persisted.
    pub fn rsa_verify_context() -> io::Result<CryptProv> {
        unsafe {
            let mut prov = 0;
            let res = advapi32::CryptAcquireContextW(&mut prov,
                                                     ptr::null_mut(),
                                                     ptr::null_mut(),
                                                     winapi::PROV_RSA_FULL,
                                                     winapi::CRYPT_VERIFYCONTEXT);
            if res == winapi::TRUE {
                Ok(CryptProv(prov))
            } else {
                Err(io::Error::last_os_error())
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn rsa_verify_context() {
        CryptProv::rsa_verify_context().unwrap();
    }
}
