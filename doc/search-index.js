var searchIndex = {};
searchIndex["schannel"] = {"doc":"Bindings to the Windows SChannel APIs.","items":[[0,"cert_context","schannel","Bindings to winapi&#39;s `PCCERT_CONTEXT` APIs.",null,null],[3,"CertContext","schannel::cert_context","Wrapper of a winapi certificate, or a `PCCERT_CONTEXT`.",null,null],[3,"AcquirePrivateKeyOptions","","A builder type for certificate private key lookup.",null,null],[11,"fmt","","",0,null],[11,"new","","Creates a new certificate from the encoded form.",0,null],[11,"sha1","","Returns the sha1 hash of this certificate",0,null],[11,"sign_hash_algorithms","","Returns the `&lt;SIGNATURE&gt;/&lt;HASH&gt;` string representing the certificate\nsignature.",0,null],[11,"signature_hash","","Returns the signature hash.",0,null],[11,"description","","Returns the property displayed by the certificate UI. This property\nallows the user to describe the certificate&#39;s use.",0,null],[11,"friendly_name","","Returns a string that contains the display name for the certificate.",0,null],[11,"set_friendly_name","","Configures the string that contains the display name for this\ncertificate.",0,null],[11,"is_time_valid","","Verifies the time validity of this certificate relative to the system&#39;s\ncurrent time.",0,null],[11,"private_key","","Returns a builder used to acquire the private key corresponding to this certificate.",0,null],[11,"delete","","Deletes this certificate from its certificate store.",0,null],[11,"compare_key","","If set, the certificate&#39;s public key will be compared with the private key to ensure a\nmatch.",1,null],[11,"silent","","If set, the lookup will not display any user interface, even if that causes the lookup to\nfail.",1,null],[11,"acquire","","Acquires the private key handle.",1,null],[11,"clone","","",0,null],[11,"drop","","",0,null],[0,"cert_store","schannel","Bindings to winapi&#39;s certificate-store related APIs.",null,null],[3,"CertStore","schannel::cert_store","Representation of certificate store on Windows, wrapping a `HCERTSTORE`.",null,null],[3,"Certs","","An iterator over the certificates contained in a `CertStore`, returned by\n`CertStore::iter`",null,null],[3,"PfxImportOptions","","A builder type for imports of PKCS #12 archives.",null,null],[4,"CertAdd","","Argument to the `add_cert` function indicating how a certificate should be\nadded to a `CertStore`.",null,null],[13,"Always","","The function makes no check for an existing matching certificate or link\nto a matching certificate. A new certificate is always added to the\nstore. This can lead to duplicates in a store.",2,null],[13,"New","","If a matching certificate or a link to a matching certificate exists,\nthe operation fails.",2,null],[13,"Newer","","If a matching certificate or a link to a matching certificate exists and\nthe NotBefore time of the existing context is equal to or greater than\nthe NotBefore time of the new context being added, the operation fails.",2,null],[13,"NewerInheritProperties","","If a matching certificate or a link to a matching certificate exists and\nthe NotBefore time of the existing context is equal to or greater than\nthe NotBefore time of the new context being added, the operation fails.",2,null],[13,"ReplaceExisting","","If a link to a matching certificate exists, that existing certificate or\nlink is deleted and a new certificate is created and added to the store.\nIf a matching certificate or a link to a matching certificate does not\nexist, a new link is added.",2,null],[13,"ReplaceExistingInheritProperties","","If a matching certificate exists in the store, the existing context is\nnot replaced. The existing context inherits properties from the new\ncertificate.",2,null],[13,"UseExisting","","If a matching certificate or a link to a matching certificate exists,\nthat existing certificate or link is used and properties from the\nnew certificate are added. The function does not fail, but it does\nnot add a new context. The existing context is duplicated and returned.",2,null],[11,"fmt","","",3,null],[11,"drop","","",3,null],[11,"clone","","",3,null],[11,"open_current_user","","Opens up the specified key store within the context of the current user.",3,{"inputs":[{"name":"str"}],"output":{"name":"result"}}],[11,"open_local_machine","","Opens up the specified key store within the context of the local\nmachine.",3,{"inputs":[{"name":"str"}],"output":{"name":"result"}}],[11,"import_pkcs12","","Imports a PKCS#12-encoded key/certificate pair, returned as a\n`CertStore` instance.",3,null],[11,"certs","","Returns an iterator over the certificates in this certificate store.",3,null],[11,"add_cert","","Adds a certificate context to this store.",3,null],[11,"next","","",4,null],[11,"default","","",5,{"inputs":[],"output":{"name":"pfximportoptions"}}],[11,"new","","Returns a new `PfxImportOptions` with default settings.",5,{"inputs":[],"output":{"name":"pfximportoptions"}}],[11,"password","","Sets the password to be used to decrypt the archive.",5,null],[11,"no_persist_key","","If set, the private key in the archive will not be persisted.",5,null],[11,"include_extended_properties","","If set, all extended properties of the certificate will be imported.",5,null],[11,"import","","Imports certificates from a PKCS #12 archive, returning a `CertStore` containing them.",5,null],[0,"key_handle","schannel","Private keys.",null,null],[3,"KeyHandle","schannel::key_handle","A handle to a private key.",null,null],[11,"drop","","",6,null],[0,"schannel_cred","schannel","Schannel credentials.",null,null],[3,"Builder","schannel::schannel_cred","A builder type for `SchannelCred`s.",null,null],[3,"SchannelCred","","An SChannel credential.",null,null],[4,"Direction","","The communication direction that an `SchannelCred` will support.",null,null],[13,"Inbound","","Server-side, inbound connections.",7,null],[13,"Outbound","","Client-side, outbound connections.",7,null],[4,"Algorithm","","Algorithms supported by Schannel.",null,null],[13,"Aes","","Advanced Encryption Standard (AES).",8,null],[13,"Aes128","","128 bit AES.",8,null],[13,"Aes192","","192 bit AES.",8,null],[13,"Aes256","","256 bit AES.",8,null],[13,"AgreedkeyAny","","Temporary algorithm identifier for handles of Diffie-Hellman–agreed keys.",8,null],[13,"CylinkMek","","An algorithm to create a 40-bit DES key that has parity bits and zeroed key bits to make\nits key length 64 bits.",8,null],[13,"Des","","DES encryption algorithm.",8,null],[13,"Desx","","DESX encryption algorithm.",8,null],[13,"DhEphem","","Diffie-Hellman ephemeral key exchange algorithm.",8,null],[13,"DhSf","","Diffie-Hellman store and forward key exchange algorithm.",8,null],[13,"DssSign","","DSA public key signature algorithm.",8,null],[13,"Ecdh","","Elliptic curve Diffie-Hellman key exchange algorithm.",8,null],[13,"Ecdsa","","Elliptic curve digital signature algorithm.",8,null],[13,"HashReplaceOwf","","One way function hashing algorithm.",8,null],[13,"HughesMd5","","Hughes MD5 hashing algorithm.",8,null],[13,"Hmac","","HMAC keyed hash algorithm.",8,null],[13,"Mac","","MAC keyed hash algorithm.",8,null],[13,"Md2","","MD2 hashing algorithm.",8,null],[13,"Md4","","MD4 hashing algorithm.",8,null],[13,"Md5","","MD5 hashing algorithm.",8,null],[13,"NoSign","","No signature algorithm..",8,null],[13,"Rc2","","RC2 block encryption algorithm.",8,null],[13,"Rc4","","RC4 stream encryption algorithm.",8,null],[13,"Rc5","","RC5 block encryption algorithm.",8,null],[13,"RsaKeyx","","RSA public key exchange algorithm.",8,null],[13,"RsaSign","","RSA public key signature algorithm.",8,null],[13,"Sha1","","SHA hashing algorithm.",8,null],[13,"Sha256","","256 bit SHA hashing algorithm.",8,null],[13,"Sha384","","384 bit SHA hashing algorithm.",8,null],[13,"Sha512","","512 bit SHA hashing algorithm.",8,null],[13,"TripleDes","","Triple DES encryption algorithm.",8,null],[13,"TripleDes112","","Two-key triple DES encryption with effective key length equal to 112 bits.",8,null],[4,"Protocol","","Protocols supported by Schannel.",null,null],[13,"Ssl3","","Secure Sockets Layer 3.0",9,null],[13,"Tls10","","Transport Layer Security 1.0",9,null],[13,"Tls11","","Transport Layer Security 1.1",9,null],[13,"Tls12","","Transport Layer Security 1.2",9,null],[11,"fmt","","",7,null],[11,"clone","","",7,null],[11,"eq","","",7,null],[11,"fmt","","",8,null],[11,"clone","","",8,null],[11,"fmt","","",9,null],[11,"clone","","",9,null],[11,"default","","",10,{"inputs":[],"output":{"name":"builder"}}],[11,"fmt","","",10,null],[11,"new","","Returns a new `Builder`.",10,{"inputs":[],"output":{"name":"builder"}}],[11,"supported_algorithms","","Sets the algorithms supported for credentials created from this builder.",10,null],[11,"enabled_protocols","","Sets the protocols enabled for credentials created from this builder.",10,null],[11,"cert","","Add a certificate to get passed down when the credentials are acquired.",10,null],[11,"acquire","","Creates a new `SchannelCred`.",10,null],[11,"drop","","",11,null],[11,"builder","","Returns a builder.",11,{"inputs":[],"output":{"name":"builder"}}],[0,"tls_stream","schannel","Schannel TLS streams.",null,null],[3,"Builder","schannel::tls_stream","A builder type for `TlsStream`s.",null,null],[3,"TlsStream","","An Schannel TLS stream.",null,null],[3,"MidHandshakeTlsStream","","A stream which has not yet completed its handshake.",null,null],[4,"HandshakeError","","A failure which can happen during the `Builder::initialize` phase, either an\nI/O error or an intermediate stream which has not completed its handshake.",null,null],[13,"Failure","","A fatal I/O error occurred",12,null],[13,"Interrupted","","The stream connection is in progress, but the handshake is not completed\nyet.",12,null],[11,"default","","",13,{"inputs":[],"output":{"name":"builder"}}],[11,"fmt","","",13,null],[11,"new","","Returns a new `Builder`.",13,{"inputs":[],"output":{"name":"builder"}}],[11,"domain","","Sets the domain associated with connections created with this `Builder`.",13,null],[11,"cert_store","","Specifies a custom certificate store which is later used when validating\na server&#39;s certificate.",13,null],[11,"connect","","Initialize a new TLS session where the stream provided will be\nconnecting to a remote TLS server.",13,null],[11,"accept","","Initialize a new TLS session where the stream provided will be\naccepting a connection.",13,null],[11,"fmt","","",12,null],[11,"description","","",12,null],[11,"cause","","",12,null],[11,"fmt","","",12,null],[11,"fmt","","",14,null],[11,"fmt","","",15,null],[11,"get_ref","","Returns a reference to the wrapped stream.",15,null],[11,"get_mut","","Returns a mutable reference to the wrapped stream.",15,null],[11,"get_buf","","Returns a reference to the buffer of pending data.",15,null],[11,"shutdown","","Shuts the TLS session down.",15,null],[11,"get_ref","","Returns a shared reference to the inner stream.",14,null],[11,"get_mut","","Returns a mutable reference to the inner stream.",14,null],[11,"handshake","","Restarts the handshake process.",14,null],[11,"write","","",15,null],[11,"flush","","",15,null],[11,"read","","",15,null],[11,"fill_buf","","",15,null],[11,"consume","","",15,null]],"paths":[[3,"CertContext"],[3,"AcquirePrivateKeyOptions"],[4,"CertAdd"],[3,"CertStore"],[3,"Certs"],[3,"PfxImportOptions"],[3,"KeyHandle"],[4,"Direction"],[4,"Algorithm"],[4,"Protocol"],[3,"Builder"],[3,"SchannelCred"],[4,"HandshakeError"],[3,"Builder"],[3,"MidHandshakeTlsStream"],[3,"TlsStream"]]};
initSearch(searchIndex);
