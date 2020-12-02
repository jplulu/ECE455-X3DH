import secrets

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from xeddsa.implementations import XEdDSA25519
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Local imports
from models import ECPublicKey, OT_PKey, Message
from util import diffie_hellman, key_derivation, decrypt_message, encrypt_message
from repository import PublicKeyRepository, OneTimeKeyRepository, MessageRepository
from KeyPair import KeyPair

class User:
    def __init__(self):
        self.ik = None
        self.spk = None
        self.key = None
        self.opk = []
        self.public_key_repository = PublicKeyRepository()
        self.one_time_repository = OneTimeKeyRepository()
        self.message_repository = MessageRepository()
        self.set_keys()  # Remove later

    def set_keys(self):
        """
        Sets the keys for a new user
        :return: None
        """
        self.ik = KeyPair.generate_key_pair()
        self.spk = KeyPair.generate_key_pair()
        self.key = KeyPair.generate_key_pair()

    def publish_keys(self, opk_count):
        """
        Publishes a bundle of public keys to the server
        :param opk_count: Number of One time pre-keys to create when the public key bundle is published
        :return: None
        """
        spk_sig = XEdDSA25519(mont_priv=self.ik.private_key).sign(self.spk.private_key)
        ec_public_key = ECPublicKey(self.ik.public_key, self.spk.public_key, spk_sig)
        while opk_count > 0:
            ot_pkey_set = KeyPair.generate_key_pair()
            self.opk.append(ot_pkey_set)    # Append KeyPair to list of opks
            ec_public_key.opks.append(ot_pkey_set.public_key)
            opk_count -= 1

        # TODO: Authentication

        # Insert public keys into table
        self.public_key_repository.insert_public_key_bundle(ec_public_key=ec_public_key)

    def key_agreement_active(self, id: int, use_opk: bool = True):
        """
        Generates a Shared Key, SK using the public key bundle
        :param use_opk:
        :param id: Use the pre-key
        :return: relevant data for first message
        """

        ec_public_key = self._retrieve_key_bundle_for_handshake_by_id(id=id)

        # Local vars
        ik_b = ec_public_key.ik
        spk_b = ec_public_key.spk
        spk_sig_b = ec_public_key.spk_sig



        # Verity the signature
        if not XEdDSA25519(mont_pub=ik_b).verify(
                spk_b,
                spk_sig_b
        ):
            print("The signature of this public bundle's spk could not be verified")
            return "The signature of this public bundle's spk could not be verified"

        EK = KeyPair.generate_key_pair()
        DH1 = diffie_hellman(self.ik.public_key, spk_b)
        DH2 = diffie_hellman(EK.public_key, ik_b)
        DH3 = diffie_hellman(EK.public_key, spk_b)
        DH4 = b""

        opk = None
        if use_opk:
            opk = self.one_time_repository.get_one_ot_pkey_by_bundle_id(ec_public_key.id)
            if opk is not None:
                DH4 = diffie_hellman(EK.private_key, opk.opk)
                self.one_time_repository.delete_ot_pkey_by_id(opk.id)  # delete opk after use


        SK = key_derivation(DH1 + DH2 + DH3 + DH4)

        # TODO: Calculate "associated data" (ad) here
        ad = self.ik.public_key + ik_b

        return SK, ad, self.ik.public_key, EK.public_key, opk, spk_b

    def _retrieve_key_bundle_for_handshake_by_id(self, id: int) -> ECPublicKey:
        """
        Gets the public key bundle for a user with the given id
        :param id: id for the public key bundle
        :return: the public key bundle for the given id
        """
        ec_public_key = self.public_key_repository.get_public_key_bundle_by_id(id=id)
        return ec_public_key


if __name__ == "__main__":

    # Receiver publishes keys to the server
    # receiver = User()
    # receiver.publish_keys(opk_count=1)

    # Sender gets the bundle and creates the shared key
    sender = User()
    SK, ad, ik_pub, EK_a_pub, opk, spk_b = sender.key_agreement_active(id=24, use_opk=True)

    enc = encrypt_message("NaM STFU WEEBS NaM", SK)
    print(enc)
    dec = decrypt_message(enc, SK)
    print(dec)