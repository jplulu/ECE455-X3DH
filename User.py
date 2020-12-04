import secrets

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from xeddsa.implementations import XEdDSA25519
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from base64 import b64encode, b64decode
from aead import AEAD

# Local imports
from models import ECPublicKey, OT_PKey, Message
from util import diffie_hellman, key_derivation, decrypt_message, encrypt_message
from repository import PublicKeyRepository, OneTimeKeyRepository, MessageRepository, existing_ik
from KeyPair import KeyPair


class User:
    def __init__(self, login):
        self.login = login
        self.ik = None
        self.spk = None
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

    def publish_keys(self, opk_count):
        """
        Publishes a bundle of public keys to the server
        :param opk_count: Number of One time pre-keys to create when the public key bundle is published
        :return: None
        """
        spk_sig = XEdDSA25519(mont_priv=self.ik.private_key).sign(self.spk.public_key)
        ec_public_key = ECPublicKey(self.ik.public_key, self.spk.public_key, spk_sig)

        while opk_count > 0:
            ot_pkey_set = KeyPair.generate_key_pair()
            self.opk.append(ot_pkey_set)    # Append KeyPair to list of opks
            ec_public_key.opks.append(OT_PKey(opk=ot_pkey_set.public_key))
            opk_count -= 1

        # TODO: Authentication
        ik_match = existing_ik(self.login, self.ik.public_key)
        # Insert public keys into table
        if ik_match == True:
            self.public_key_repository.insert_public_key_bundle(ec_public_key=ec_public_key)
        else:
            print("Error: Mismatched identity key")

    def initiate_handshake(self, id: int, use_opk: bool = True):
        """
        Generates a Shared Key, SK using the public key bundle
        :param use_opk:
        :param id: Use the pre-key
        :return: relevant data for first message
        """

        ec_public_key = self._retrieve_key_bundle_for_handshake_by_id(id=id)
        # print(ec_public_key)

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
        DH1 = diffie_hellman(self.ik.private_key, spk_b)
        DH2 = diffie_hellman(EK.private_key, ik_b)
        DH3 = diffie_hellman(EK.private_key, spk_b)
        DH4 = b""

        opk = None
        if use_opk:
            opk = self.one_time_repository.get_one_ot_pkey_by_bundle_id(ec_public_key.id)
            if opk is not None:
                DH4 = diffie_hellman(EK.private_key, opk.opk)
                self.one_time_repository.delete_ot_pkey_by_id(opk.id)  # delete opk after use


        # Create the shared key
        SK = key_derivation(DH1 + DH2 + DH3 + DH4)

        # Calculate the associated data
        ad = self.ik.public_key + ik_b

        # Encrypt initial message with the shared key, including the associated data
        cryptor = AEAD(b64encode(SK))
        msg = cryptor.encrypt(b"NaM STFU WEEBS NaM", ad)
        message = Message(receiver_id=ec_public_key.id,
                          sender_id=1,
                          sender_ik=self.ik.public_key,
                          sender_ek=EK.public_key,
                          message=msg)

        # Post message to server with the correct key bundle
        self.message_repository.insert_message(message=message)

        # return SK, ad, self.ik.public_key, EK.public_key, opk, spk_b

    def complete_handshake(self, id: int, use_opk: bool = False):
        # Get the initiate handshake message
        message = self.message_repository.get_messages_by_receiver_id(receiver_id=id)


        # Perform Diffie-Hellman to get Shared Key
        DH1 = diffie_hellman(self.spk.private_key, message.sender_ik)
        DH2 = diffie_hellman(self.ik.private_key, message.sender_ek)
        DH3 = diffie_hellman(self.spk.private_key, message.sender_ek)
        DH4 = b""

        opk = None
        if use_opk:
            pass


        # Calculate the shared key
        SK = key_derivation(DH1 + DH2 + DH3 + DH4)

        # Calculate the associated data
        ad = message.sender_ik + self.ik.public_key
        msg = self._check_associated_data(message=message.message, associated_data=ad, shared_key=SK)
        if msg is None:
            return None
        else:
            print(msg)
            return SK

    def _retrieve_key_bundle_for_handshake_by_id(self, id: int) -> ECPublicKey:
        """
        Gets the public key bundle for a user with the given id
        :param id: id for the public key bundle
        :return: the public key bundle for the given id
        """
        ec_public_key = self.public_key_repository.get_public_key_bundle_by_id(id=id)
        return ec_public_key

    def _check_associated_data(self, message: bytes, associated_data: bytes, shared_key: bytes) -> str:
        """
        Checks the associated data of the message initiating the handshake
        :param message: the Message
        :return: True if matching, else False(
        """
        cryptor = AEAD(b64encode(shared_key))
        try:
            dec = cryptor.decrypt(message, associated_data)
        except ValueError as e:
            print(e)
            return None
        return dec
    def save_keys(self, filename: str) -> None:
        """
        Saves the public and private identity and pre-keys to a file
        :param filename: file to save the keys
        :return:None
        """
        text = ""
        text += "identity key, {}, {}\n".format(self.ik.private_key, self.ik.public_key)
        text += "pre-key, {}, {}\n".format(self.spk.private_key, self.spk.public_key)
        text += "one-time, {}".format(self.opk)
        with open(filename, 'w') as f:
            f.write(text)

    def load_keys(self, filename: str) -> None:
        """
        Loads public and private keys that were stored in a file
        :param filename: file to load keys
        :return: None
        """
        try:
            with open(filename, 'r') as f:
                text = f.read().split("\n")
                ik = text[0].split(",")
                spk = text[1].split(",")
                self.ik = KeyPair(private_key=b64encode(ik[1]), public_key=b64encode(ik[2]))
                self.spk = KeyPair(private_key=b64encode(spk[1]), public_key=b64encode(spk[2]))
        except FileNotFoundError:
            print("Cannot find key file")

if __name__ == "__main__":

    # Receiver publishes keys to the server
    # receiver.publish_keys(opk_count=1)

    # Sender gets the bundle and creates the shared key
    sender = User()
    sender.publish_keys(opk_count=0)
    # sender.save_keys('sender.txt')
    # sender.load_keys('sender.txt')

    receiver = User()
    receiver.publish_keys(opk_count=0)
    # print(PublicKeyRepository().get_all_public_key_bundles())
    # receiver.save_keys('receiver.txt')
    # receiver.load_keys('receiver.txt')
    sender.initiate_handshake(id=2, use_opk=False)
    receiver.complete_handshake(id=2)




