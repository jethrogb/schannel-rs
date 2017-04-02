//! Bindings to winapi's `PCCERT_CONTEXT` APIs.

use std::ffi::OsString;
use std::io;
use std::mem;
use std::os::windows::prelude::*;
use std::ptr;
use std::slice;
use crypt32;
use winapi;

use {Inner, KeyHandlePriv};
use key_handle::KeyHandle;
use ncrypt_key::NcryptKey;
use crypt_prov::CryptProv;

// FIXME https://github.com/retep998/winapi-rs/pull/318
const CRYPT_ACQUIRE_COMPARE_KEY_FLAG: winapi::DWORD = 0x4;
const CRYPT_ACQUIRE_SILENT_FLAG: winapi::DWORD = 0x40;
const CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG: winapi::DWORD = 0x10000;

// FIXME
const CRYPT_STRING_BASE64HEADER: winapi::DWORD = 0x0;

/// Wrapper of a winapi certificate, or a `PCCERT_CONTEXT`.
#[derive(Debug)]
pub struct CertContext(winapi::PCCERT_CONTEXT);

unsafe impl Sync for CertContext {}
unsafe impl Send for CertContext {}

impl Drop for CertContext {
    fn drop(&mut self) {
        unsafe {
            crypt32::CertFreeCertificateContext(self.0);
        }
    }
}

impl Clone for CertContext {
    fn clone(&self) -> CertContext {
        unsafe { CertContext(crypt32::CertDuplicateCertificateContext(self.0)) }
    }
}

impl Inner<winapi::PCCERT_CONTEXT> for CertContext {
    unsafe fn from_inner(t: winapi::PCCERT_CONTEXT) -> CertContext {
        CertContext(t)
    }

    fn as_inner(&self) -> winapi::PCCERT_CONTEXT {
        self.0
    }

    fn get_mut(&mut self) -> &mut winapi::PCCERT_CONTEXT {
        &mut self.0
    }
}

impl CertContext {
    /// Decodes a DER-formatted X509 certificate.
    pub fn new(data: &[u8]) -> io::Result<CertContext> {
        let ret = unsafe {
            crypt32::CertCreateCertificateContext(winapi::X509_ASN_ENCODING |
                                                  winapi::PKCS_7_ASN_ENCODING,
                                                  data.as_ptr(),
                                                  data.len() as winapi::DWORD)
        };
        if ret.is_null() {
            Err(io::Error::last_os_error())
        } else {
            Ok(CertContext(ret))
        }
    }

    /// Decodes a PEM-formatted X509 certificate.
    pub fn from_pem(pem: &str) -> io::Result<CertContext> {
        unsafe {
            assert!(pem.len() <= winapi::DWORD::max_value() as usize);

            let mut len = 0;
            let ok = crypt32::CryptStringToBinaryA(pem.as_ptr() as winapi::LPCSTR,
                                                   pem.len() as winapi::DWORD,
                                                   CRYPT_STRING_BASE64HEADER,
                                                   ptr::null_mut(),
                                                   &mut len,
                                                   ptr::null_mut(),
                                                   ptr::null_mut());
            if ok != winapi::TRUE {
                return Err(io::Error::last_os_error());
            }

            let mut buf = vec![0; len as usize];
            let ok = crypt32::CryptStringToBinaryA(pem.as_ptr() as winapi::LPCSTR,
                                                   pem.len() as winapi::DWORD,
                                                   CRYPT_STRING_BASE64HEADER,
                                                   buf.as_mut_ptr(),
                                                   &mut len,
                                                   ptr::null_mut(),
                                                   ptr::null_mut());
            if ok != winapi::TRUE {
                return Err(io::Error::last_os_error());
            }

            CertContext::new(&buf)
        }
    }

    /// Returns the sha1 hash of this certificate
    ///
    /// The sha1 is returned as a 20-byte array representing the bits of the
    /// sha1 hash.
    pub fn sha1(&self) -> io::Result<[u8; 20]> {
        unsafe {
            let mut buf = [0; 20];
            let mut len = buf.len() as winapi::DWORD;
            let ret = crypt32::CertGetCertificateContextProperty(self.0,
                                                                 winapi::CERT_SHA1_HASH_PROP_ID,
                                                                 buf.as_mut_ptr() as
                                                                 *mut winapi::c_void,
                                                                 &mut len);
            if ret != winapi::TRUE {
                return Err(io::Error::last_os_error());
            }
            Ok(buf)
        }
    }

    /// Returns the `<SIGNATURE>/<HASH>` string representing the certificate
    /// signature.
    ///
    /// The `<SIGNATURE>` value identifies the CNG public key
    /// algorithm. The `<HASH>` value identifies the CNG hash algorithm.
    ///
    /// Common examples are:
    ///
    /// * `RSA/SHA1`
    /// * `RSA/SHA256`
    /// * `ECDSA/SHA256`
    pub fn sign_hash_algorithms(&self) -> io::Result<String> {
        self.get_string(winapi::CERT_SIGN_HASH_CNG_ALG_PROP_ID)
    }

    /// Returns the signature hash.
    pub fn signature_hash(&self) -> io::Result<Vec<u8>> {
        self.get_bytes(winapi::CERT_SIGNATURE_HASH_PROP_ID)
    }

    /// Returns the property displayed by the certificate UI. This property
    /// allows the user to describe the certificate's use.
    pub fn description(&self) -> io::Result<Vec<u8>> {
        self.get_bytes(winapi::CERT_DESCRIPTION_PROP_ID)
    }

    /// Returns a string that contains the display name for the certificate.
    pub fn friendly_name(&self) -> io::Result<String> {
        self.get_string(winapi::CERT_FRIENDLY_NAME_PROP_ID)
    }

    /// Configures the string that contains the display name for this
    /// certificate.
    pub fn set_friendly_name(&self, name: &str) -> io::Result<()> {
        self.set_string(winapi::CERT_FRIENDLY_NAME_PROP_ID, name)
    }

    /// Verifies the time validity of this certificate relative to the system's
    /// current time.
    pub fn is_time_valid(&self) -> io::Result<bool> {
        let ret = unsafe { crypt32::CertVerifyTimeValidity(ptr::null_mut(), (*self.0).pCertInfo) };
        Ok(ret == 0)
    }

    /// Returns a builder used to acquire the private key corresponding to this certificate.
    pub fn private_key<'a>(&'a self) -> AcquirePrivateKeyOptions<'a> {
        AcquirePrivateKeyOptions {
            cert: self,
            flags: 0,
        }
    }

    /// Deletes this certificate from its certificate store.
    pub fn delete(self) -> io::Result<()> {
        unsafe {
            let ret = crypt32::CertDeleteCertificateFromStore(self.0);
            mem::forget(self);
            if ret == winapi::TRUE {
                Ok(())
            } else {
                Err(io::Error::last_os_error())
            }
        }
    }

    fn get_encoded_bytes(&self) -> &[u8] {
        unsafe {
            let cert_ctx = *self.0;
            slice::from_raw_parts(cert_ctx.pbCertEncoded, cert_ctx.cbCertEncoded as usize)
        }
    }

    fn get_bytes(&self, prop: winapi::DWORD) -> io::Result<Vec<u8>> {
        unsafe {
            let mut len = 0;
            let ret =
                crypt32::CertGetCertificateContextProperty(self.0, prop, ptr::null_mut(), &mut len);
            if ret != winapi::TRUE {
                return Err(io::Error::last_os_error());
            }

            let mut buf = vec![0u8; len as usize];
            let ret = crypt32::CertGetCertificateContextProperty(self.0,
                                                                 prop,
                                                                 buf.as_mut_ptr() as
                                                                 *mut winapi::c_void,
                                                                 &mut len);
            if ret != winapi::TRUE {
                return Err(io::Error::last_os_error());
            }
            Ok(buf)
        }
    }

    fn get_string(&self, prop: winapi::DWORD) -> io::Result<String> {
        unsafe {
            let mut len = 0;
            let ret =
                crypt32::CertGetCertificateContextProperty(self.0, prop, ptr::null_mut(), &mut len);
            if ret != winapi::TRUE {
                return Err(io::Error::last_os_error());
            }

            // Divide by 2 b/c `len` is the byte length, but we're allocating
            // u16 pairs which are 2 bytes each.
            let amt = (len / 2) as usize;
            let mut buf = vec![0u16; amt];
            let ret = crypt32::CertGetCertificateContextProperty(self.0,
                                                                 prop,
                                                                 buf.as_mut_ptr() as
                                                                 *mut winapi::c_void,
                                                                 &mut len);
            if ret != winapi::TRUE {
                return Err(io::Error::last_os_error());
            }

            // Chop off the trailing nul byte
            Ok(OsString::from_wide(&buf[..amt - 1]).into_string().unwrap())
        }
    }

    fn set_string(&self, prop: winapi::DWORD, s: &str) -> io::Result<()> {
        unsafe {
            let data = s.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
            let data = winapi::CRYPT_DATA_BLOB {
                cbData: (data.len() * 2) as winapi::DWORD,
                pbData: data.as_ptr() as *mut _,
            };
            let ret = crypt32::CertSetCertificateContextProperty(self.0,
                                                                 prop,
                                                                 0,
                                                                 &data as *const _ as *const _);
            if ret != winapi::TRUE {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        }
    }
}

impl PartialEq for CertContext {
    fn eq(&self, other: &CertContext) -> bool {
        self.get_encoded_bytes() == other.get_encoded_bytes()
    }
}

/// A builder type for certificate private key lookup.
pub struct AcquirePrivateKeyOptions<'a> {
    cert: &'a CertContext,
    flags: winapi::DWORD,
}

impl<'a> AcquirePrivateKeyOptions<'a> {
    /// If set, the certificate's public key will be compared with the private key to ensure a
    /// match.
    pub fn compare_key(&mut self, compare_key: bool) -> &mut AcquirePrivateKeyOptions<'a> {
        self.flag(CRYPT_ACQUIRE_COMPARE_KEY_FLAG, compare_key)
    }

    /// If set, the lookup will not display any user interface, even if that causes the lookup to
    /// fail.
    pub fn silent(&mut self, silent: bool) -> &mut AcquirePrivateKeyOptions<'a> {
        self.flag(CRYPT_ACQUIRE_SILENT_FLAG, silent)
    }

    fn flag(&mut self, flag: winapi::DWORD, set: bool) -> &mut AcquirePrivateKeyOptions<'a> {
        if set {
            self.flags |= flag;
        } else {
            self.flags &= !flag;
        }
        self
    }

    /// Acquires the private key handle.
    pub fn acquire(&self) -> io::Result<PrivateKey> {
        unsafe {
            let flags = self.flags | CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG;
            let mut handle = 0;
            let mut spec = 0;
            let mut free = winapi::FALSE;
            let res = crypt32::CryptAcquireCertificatePrivateKey(self.cert.0,
                                                                 flags,
                                                                 ptr::null_mut(),
                                                                 &mut handle,
                                                                 &mut spec,
                                                                 &mut free);
            if res != winapi::TRUE {
                return Err(io::Error::last_os_error());
            }
            assert!(free == winapi::TRUE);
            if spec & winapi::CERT_NCRYPT_KEY_SPEC != 0 {
                Ok(PrivateKey::NcryptKey(NcryptKey::from_inner(handle)))
            } else {
                Ok(PrivateKey::CryptProv(CryptProv::from_inner(handle)))
            }
        }
    }
}

/// The private key associated with a certificate context.
pub enum PrivateKey {
    /// A CryptoAPI provider.
    CryptProv(CryptProv),
    /// A CNG provider.
    NcryptKey(NcryptKey),
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn decode() {
        let der = include_bytes!("../test/cert.der");
        let pem = include_str!("../test/cert.pem");

        let der = CertContext::new(der).unwrap();
        let pem = CertContext::from_pem(pem).unwrap();
        assert_eq!(der, pem);
    }
}
