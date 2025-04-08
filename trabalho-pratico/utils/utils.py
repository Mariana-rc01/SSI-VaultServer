import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dh, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography import x509
import datetime

p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
g = 2

HARDCODED_AES_KEY = b"12345678901234567890123456789012"

def generate_private_key():
    parameters = dh.DHParameterNumbers(p,g).parameters()
    return parameters.generate_private_key()

def generate_public_key(private_key):
    return private_key.public_key()

def generate_shared_key(private_key, public_key):
    return private_key.exchange(public_key)

def generate_derived_key(shared_key):
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
    ).derive(shared_key)
    return derived_key

def serialize_public_key(public_key: dh.DHPublicKey):
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return pem

def deserialize_public_key(serialized_public_key):
    return serialization.load_pem_public_key(serialized_public_key, default_backend())

def encrypt(content, aesgcm):
    nonce = os.urandom(12)
    encrypted = aesgcm.encrypt(nonce, content, None)
    return nonce+encrypted

def decrypt(content, aesgcm):
    nonce = content[:12]
    real_content = content[12:]
    ct = aesgcm.decrypt(nonce, real_content, None)
    return ct

def build_aesgcm(key):
    return AESGCM(key)

def request(type, args):
    return {
        "type": type,
        "args": args
    }

# Certificates
certificates_path = "./certificates"
ca_certificate_path = os.path.join(certificates_path, "VAULT_CA.crt")

def certificate_load(fname):
    """reads a certificate from file"""
    with open(os.path.join(certificates_path, fname), 'rb') as f:
        cert = x509.load_pem_x509_certificate(f.read())

    return cert

def certificate_create(content):
    return x509.load_pem_x509_certificate(content)

def serialize_certificate(certificate):
    """serializes a certificate to PEM format"""
    return certificate.public_bytes(
        encoding=serialization.Encoding.PEM
    )

def is_certificate_valid(certificate: x509.Certificate, common_name: str):
    try:
        ca_certificate = certificate_load("VAULT_CA.crt")
        validate_certificate_issuer(certificate, ca_certificate)
        certificate_validsubject(
            certificate, [(x509.NameOID.COMMON_NAME, common_name)]
        )

        certificate_validtime(certificate)
        # validate_certificate_extensions(certificate, {x509.ExtensionOID.KEY_USAGE: lambda ext: x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH in ext})
    except Exception as e:
        print(f"Certificate validation failed: {e}")
        return False

    return True

def validate_certificate_issuer(
    certificate: x509.Certificate, ca_certificate: x509.Certificate
):
    # Assuming the chain has only 2 levels
    try:
        certificate.verify_directly_issued_by(ca_certificate)
    except:
        raise x509.verification.VerificationError(
            "Certificate is not directly issued by the CA"
        )

def certificate_validtime(cert, now=None):
    """returns where 'now' is in the validity period of the certificate"""
    if now is None:
        now = datetime.datetime.now(tz=datetime.timezone.utc)
    if now < cert.not_valid_before_utc or now > cert.not_valid_after_utc:
        raise x509.verification.VerificationError(
            "Certificate is not valid at this time"
        )

def certificate_validsubject(cert, attrs=[]):
    """Verify the 'subject' attributes of the certificate.
    'attrs' is a list of pairs '(attr,value)' that
    checks the values of 'attr' against 'value'."""
    print(cert.subject)
    for attr in attrs:
        if cert.subject.get_attributes_for_oid(attr[0])[0].value != attr[1]:
            raise x509.verification.VerificationError(
                "Certificate subject does not match expected value"
            )

def certificate_validexts(cert, policy=[]):
    """validate the certificate extensions.
    'policy' is a list of pairs '(ext,pred)' where 'ext' is the OID of an extension and 'pred'
    is the predicate responsible for checking the content of that extension."""
    for check in policy:
        ext = cert.extensions.get_extension_for_oid(check[0]).value
        if not check[1](ext):
            raise x509.verification.VerificationError(
                "Certificate extensions does not match expected value"
            )

# RSA

keys_directory = "./keys"
password = b""

def load_rsa_private_key(filename):
    with open(os.path.join(keys_directory, filename), "rb") as f:
        return serialization.load_pem_private_key(f.read(),  None, default_backend())

def sign_message_with_rsa(message, private_key):
    return private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )

def is_signature_valid(signature, message, public_key):
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except Exception as e:
        print("Signature is invalid!")
        print(e)
        return False

# Serialization

def mkpair(x, y):
    """produces a byte-string containing the tuple '(x,y)' ('x' and 'y' are byte-strings)"""
    len_x = len(x)
    len_x_bytes = len_x.to_bytes(2, "little")
    return len_x_bytes + x + y

def unpair(xy):
    """returns the components of a pair encoded with 'mkpair'"""
    len_x = int.from_bytes(xy[:2], "little")
    x = xy[2 : len_x + 2]
    y = xy[len_x + 2 :]
    return x, y

