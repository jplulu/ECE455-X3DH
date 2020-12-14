from datetime import datetime
from xeddsa.implementations import XEdDSA25519
from base64 import b64encode, b64decode
from aead import AEAD

# Local imports
from src.models import ECPublicKey, OT_PKey, Message
from src.util import diffie_hellman, key_derivation, decrypt_message, encrypt_message
from src.repository import PublicKeyRepository, OneTimeKeyRepository, MessageRepository, UserRepository
from src.KeyPair import KeyPair


class User:
    """
    Class representing a user
    """
    def __init__(self, user=None):
        self.ik = None
        self.spk = None
        self.opk = []
        self.max_opk = 0
        self.sk = {}
        self.public_key_repository = PublicKeyRepository()
        self.one_time_repository = OneTimeKeyRepository()
        self.message_repository = MessageRepository()
        self.user_repository = UserRepository()
        self.login = user

    def set_keys(self):
        """
        Sets the keys for a new user
        :return: None
        """
        self.ik = KeyPair.generate_key_pair()
        self.spk = KeyPair.generate_key_pair()

    def set_spk(self):
        """
        Sets new SPKs for the user
        :return: None
        """
        self.spk = KeyPair.generate_key_pair()

    def publish_keys(self, opk_count):
        """
        Publishes a bundle of public keys to the server. Can be used to publish a new
        :param opk_count: Number of One time pre-keys to create when the public key bundle is published
        :return: None
        """
        spk_sig = XEdDSA25519(mont_priv=self.ik.private_key).sign(self.spk.public_key)
        ec_public_key = ECPublicKey(self.login.id, self.ik.public_key, self.spk.public_key, spk_sig)

        # CASE New SPK: Verify that the IK of the new bundle matches that of the one on the server
        existing_pkey_bundle = self.public_key_repository.get_public_key_bundle_by_id(self.login.id)
        if existing_pkey_bundle is not None and self.ik.public_key != existing_pkey_bundle.ik:
            print("Identity key cannot be changed!")
            return None

        # Add the number of OPKs specified by opk_count. Add those OPKs to the user's list of opks.
        self.max_opk = opk_count
        while opk_count > 0:
            ot_pkey_set = KeyPair.generate_key_pair()
            self.opk.append(ot_pkey_set)  # Append KeyPair to list of opks
            ec_public_key.opks.append(OT_PKey(opk=ot_pkey_set.public_key))
            opk_count -= 1

        if self.login is not None:
            # Insert public keys into table
            self.public_key_repository.insert_public_key_bundle(ec_public_key=ec_public_key)
        else:
            print("Failed to login.")

    def initiate_handshake(self, id: int, m: str = "handshake", use_opk: bool = True):
        """
        Generates a Shared Key, SK using the public key bundle
        :param m:
        :param use_opk:
        :param id: Use the pre-key
        :return: relevant data for first message
        """
        if id == self.login.id:
            print("Handshake failed: Cannot handshake with self")
            return
        if self.message_repository.get_handshake_message_by_sender_and_receiver(sender_id=id,
                                                                                receiver_id=self.login.id):
            print("Handshake already initiated by {}. Completing handshake...".format(id))
            self.complete_handshake(id=id)
            return
        ec_public_key, opk = self._retrieve_key_bundle_for_handshake_by_id(id=id)
        if ec_public_key is None:
            print("Handshake failed: Unable to retrieve key bundle for user {}".format(id))
            return

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
            return

        EK = KeyPair.generate_key_pair()
        DH1 = diffie_hellman(self.ik.private_key, spk_b)
        DH2 = diffie_hellman(EK.private_key, ik_b)
        DH3 = diffie_hellman(EK.private_key, spk_b)
        DH4 = b""

        opk_payload = None  # opk to send in message
        if use_opk:
            if opk:
                DH4 = diffie_hellman(EK.private_key, opk)
                opk_payload = opk
            else:
                print("Use opk is active but no opk is found")
                return

        # Create the shared key
        SK = key_derivation(DH1 + DH2 + DH3 + DH4)

        # Calculate the associated data
        ad = self.ik.public_key + ik_b

        # Encrypt initial message with the shared key, including the associated data
        cryptor = AEAD(b64encode(SK))
        msg = cryptor.encrypt(bytes(m, 'ASCII'), ad)
        existing_handshake = self.message_repository.get_handshake_message_by_sender_and_receiver(
            sender_id=self.login.id, receiver_id=id)
        if existing_handshake is None:
            message = Message(receiver_id=ec_public_key.id,
                              sender_id=self.login.id,
                              sender_ik=self.ik.public_key,
                              sender_ek=EK.public_key,
                              opk_used=opk_payload,
                              message=msg,
                              timestamp=datetime.now())

            # Post message to server with the correct key bundle
            self.message_repository.insert_message(message=message)
        else:
            existing_handshake.sender_ek = EK.public_key
            existing_handshake.opk_used = opk_payload
            existing_handshake.message = msg
            self.message_repository.session.commit()
        self.sk[ec_public_key.id] = SK
        print('Handshake initiated with user {}'.format(id))

    def complete_handshake(self, id: int):
        """
        Completes the handshake sent by the user with the given id
        :param id: The id of the initiating user
        :return: None
        """
        # Get the initiate handshake message
        message = self.message_repository.get_handshake_message_by_sender_and_receiver(sender_id=id,
                                                                                       receiver_id=self.login.id)
        if message is None:
            print("No handshake message found")
            return None

        # Perform Diffie-Hellman to get Shared Key
        DH1 = diffie_hellman(self.spk.private_key, message.sender_ik)
        DH2 = diffie_hellman(self.ik.private_key, message.sender_ek)
        DH3 = diffie_hellman(self.spk.private_key, message.sender_ek)
        DH4 = b""
        if message.opk_used:
            opk_priv = None
            for i, opk in enumerate(self.opk):
                if opk.public_key == message.opk_used:
                    opk_priv = opk.private_key
                    del self.opk[i]
                    break
            DH4 = diffie_hellman(opk_priv, message.sender_ek)

        # Calculate the shared key
        SK = key_derivation(DH1 + DH2 + DH3 + DH4)

        # Calculate the associated data
        ad = message.sender_ik + self.ik.public_key
        msg = self._check_associated_data(message=message.message, associated_data=ad, shared_key=SK)
        if msg is None:
            print("Failed to complete handshake: Unable to decrypt secret message")
            return None
        else:
            decoded_message = msg.decode('ASCII')
            self.sk[id] = SK
        # Remove keys used from the message
        message.sender_ik = None
        message.sender_ek = None
        message.opk_used = None
        message.message = encrypt_message(decoded_message, SK)
        self.message_repository.session.commit()
        print('Handshake completed with user {}'.format(id))

    def send_message(self, receiver_id: int, m: str):
        """
        Sends a message to the specified user, encrypted with the derived shared key
        :param receiver_id: the id of the receiver
        :param m: the message
        :return: None
        """
        if receiver_id not in self.sk:
            # Perform handshake if sk doesn't exist with receiver
            handshake_msg = self.message_repository.get_handshake_message_by_sender_and_receiver(sender_id=receiver_id,
                                                                                                 receiver_id=self.login.id)
            if handshake_msg:
                # Complete handshake if there is pending handshake from receiver
                print("Pending handshake from user {} found. Completing handshake...".format(receiver_id))
                self.complete_handshake(receiver_id)
            else:
                # Initiate handshake with intended message if there is no pending handshake from receiver
                print("No key agreement found with user {}. Initiating handshake...".format(receiver_id))
                self.initiate_handshake(id=receiver_id, m=m)
                return

        sk = self.sk[receiver_id]
        encrypted_msg = encrypt_message(m, sk)
        message = Message(receiver_id=receiver_id,
                          sender_id=self.login.id,
                          sender_ik=None,
                          sender_ek=None,
                          opk_used=None,
                          message=encrypted_msg,
                          timestamp=datetime.now())
        self.message_repository.insert_message(message=message)
        self.message_repository.session.commit()
        print("Message sent")

    def get_message_by_sender(self, sender_id: int, receiver_id: int):
        """
        Gets all of the messages sent between the users with ids sender_id and receiver_id.
        sender_id is settable for demonstration purpose.
        :param sender_id: the id of the sender (typically the id of the user who is logged in)
        :param receiver_id: the id of the receiver
        :return: None
        """
        if receiver_id == '':
            receiver_id = self.login.id
        else:
            receiver_id = int(receiver_id)
        if sender_id not in self.sk and receiver_id not in self.sk and receiver_id == self.login.id:
            # Check if there is a pending handshake from sender
            handshake_message = self.message_repository.get_handshake_message_by_sender_and_receiver(
                sender_id=sender_id, receiver_id=self.login.id)
            if handshake_message:
                # Complete handshake if there is a pending handshake
                print("Pending handshake from user {} found. Completing handshake...".format(sender_id))
                self.complete_handshake(id=sender_id)

        if sender_id in self.sk:
            key = self.sk[sender_id]
        elif receiver_id in self.sk:
            key = self.sk[receiver_id]
        else:
            key = KeyPair.generate_key_pair().public_key

        messages = self.message_repository.get_messages(sender_id=sender_id, receiver_id=receiver_id)
        if not messages:
            print("No messages found")
        else:
            print("Sender     Time            Message")
            print(40 * "-")
            for message in messages:
                msg = message.message
                print(message.sender_ik)
                if message.sender_id == self.login.id and message.sender_ik:
                    print("{}: {} -> PENDING HANDSHAKE MESSAGE".format(message.sender_id, message.timestamp))
                else:
                    decrypted_message = decrypt_message(msg, key)
                    print("{}: {} -> {}".format(message.sender_id, message.timestamp, decrypted_message))

    def save_keys(self, filename: str) -> None:
        """
        Saves the public and private identity and pre-keys to a file
        :param filename: file to save the keys
        :return:None
        """

        text = ""
        text += "identity-key,{},{}\n".format(b64encode(self.ik.private_key).decode("ASCII"),
                                              b64encode(self.ik.public_key).decode("ASCII"))
        text += "pre-key,{},{}\n".format(b64encode(self.spk.private_key).decode("ASCII"),
                                         b64encode(self.spk.public_key).decode("ASCII"))
        text += "one-time-key"
        for opk in self.opk:
            text += ",{} {}".format(b64encode(opk.private_key).decode("ASCII"),
                                    b64encode(opk.public_key).decode("ASCII"))
        text += "\nsecret-key"
        for user, key in self.sk.items():
            text += ",{} {}".format(user,
                                    b64encode(key).decode("ASCII"))
        with open(filename, 'w') as f:
            f.write(text)

    def load_keys(self, filename: str) -> None:
        """
        Loads public and private keys that were stored in a file
        :param filename: file to load keys
        :return: None
        """

        with open(filename, 'r') as f:
            text = f.read().split("\n")
            ik = text[0].split(",")[1:]
            spk = text[1].split(",")[1:]
            opks = text[2].split(",")[1:]
            sks = text[3].split(",")[1:]
            self.ik = KeyPair(private_key=b64decode(ik[0].encode("ASCII", errors="strict"), validate=True),
                              public_key=b64decode(ik[1].encode("ASCII", errors="strict"), validate=True))
            self.spk = KeyPair(private_key=b64decode(spk[0].encode("ASCII", errors="strict"), validate=True),
                               public_key=b64decode(spk[1].encode("ASCII", errors="strict"), validate=True))
            for opk in opks:
                priv, pub = opk.split()
                self.opk.append(KeyPair(b64decode(priv.encode("ASCII", errors="strict"), validate=True),
                                        b64decode(pub.encode("ASCII", errors="strict"), validate=True)))
            for sk in sks:
                user, key = sk.split()
                self.sk[int(user)] = b64decode(key.encode("ASCII", errors="strict"), validate=True)

    def _retrieve_key_bundle_for_handshake_by_id(self, id: int) -> (ECPublicKey, OT_PKey):
        """
        Gets the public key bundle for a user with the given id
        :param id: id for the public key bundle
        :return: the public key bundle for the given id
        """
        ec_public_key = self.public_key_repository.get_public_key_bundle_by_id(id=id)
        opk = self.one_time_repository.get_one_ot_pkey_by_bundle_id(id)

        # delete opk after fetch
        opk_pub = None
        if opk:
            opk_pub = opk.opk
            self.one_time_repository.delete_ot_pkey_by_id(opk.id)
        return ec_public_key, opk_pub

    def _check_associated_data(self, message: bytes, associated_data: bytes, shared_key: bytes):
        """
        Checks the associated data of the message initiating the handshake
        :param message: the Message
        :return: Decrypted string if matching, else None
        """
        cryptor = AEAD(b64encode(shared_key))
        try:
            dec = cryptor.decrypt(message, associated_data)
            return dec
        except ValueError as e:
            print("Unable to decrypt message.")
            return None