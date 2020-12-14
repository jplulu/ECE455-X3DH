from __future__ import annotations
from sqlalchemy import create_engine, or_, and_
from sqlalchemy.orm import sessionmaker
from typing import List
from sqlalchemy.exc import IntegrityError

# Local imports
from src.models import ECPublicKey, OT_PKey, Message, Login
from src import engine

# engine = create_engine('mysql://root:password@localhost/keybundle')  # connect to server
# engine = create_engine('mysql://{}:{}@localhost/keybundle'.format(db_user, db_password))  # connect to server
Session = sessionmaker(bind=engine)
session = Session()


class PublicKeyRepository:
    def __init__(self):
        self.session = session

    def insert_public_key_bundle(self, ec_public_key: ECPublicKey) -> None:
        """
        Inserts the given public key bundle. If a bundle with the same id exists, update the bundle.
        :param ec_public_key: a public key bundle
        :return: None
        """
        try:
            self.session.merge(ec_public_key)
            self.session.commit()
        except IntegrityError:
            print("Key bundle already published.")
            self.session.rollback()

    def get_all_public_key_bundles(self) -> List[ECPublicKey]:
        """
        Gets all of the public key bundles
        :return: all of the stored public key bundles
        """
        result = self.session.query(ECPublicKey)
        return [x for x in result]

    def get_public_key_bundle_by_id(self, id: int) -> ECPublicKey:
        """
        Gets the public key bundle corresponding to the given id
        :param id: the id for the desired public key bundle
        :return: the public key bundle
        """
        result = self.session.query(ECPublicKey) \
            .filter(ECPublicKey.id == id) \
            .first()
        return result

    def clear_public_key_table(self) -> None:
        """
        clears the ecpublickeys table
        :return: None
        """
        self.session.query(ECPublicKey) \
            .delete(synchronize_session=False)
        self.session.commit()


class OneTimeKeyRepository:
    def __init__(self):
        self.session = session

    def insert_ot_pkey(self, ot_pkey: OT_PKey) -> None:
        """
        Inserts the given one time pre-key into the table
        :param ot_pkey: the One Time Pre-Key
        :return: None
        """
        self.session.add(ot_pkey)
        self.session.commit()

    def get_one_ot_pkey_by_bundle_id(self, bundle_id: int) -> OT_PKey:
        """
        Gets one OT_PKey corresponding to the given id
        :param bundle_id:
        :return: A single OT_PKey
        """
        result = self.session.query(OT_PKey) \
            .filter(OT_PKey.bundle_id == bundle_id) \
            .first()
        return result

    def get_all_ot_pkeys(self):
        """
        Gets all of the ot_pkeys
        :return: all of the ot_pkeys
        """
        result = self.session.query(OT_PKey)
        return [x for x in result]

    def delete_ot_pkey_by_id(self, id):
        self.session.query(OT_PKey) \
            .filter(OT_PKey.id == id) \
            .delete(synchronize_session=False)
        self.session.commit()


class MessageRepository:
    def __init__(self):
        self.session = session

    def insert_message(self, message: Message) -> None:
        """
        Inserts a message into the database
        :param message: the (encrypted) message
        :return:
        """
        self.session.add(message)
        self.session.commit()



    def get_handshake_message_by_sender_and_receiver(self, sender_id, receiver_id) -> Message:
        """
        Gets the handshake message sent from user sender_id to receiver_id
        :param sender_id: the sending user's id
        :param receiver_id: the receiving user's id
        :return: Message
        """
        result = self.session.query(Message).filter(
            Message.sender_id == sender_id,
            Message.receiver_id == receiver_id,
            Message.sender_ik.isnot(None)
        ).first()
        return result

    def get_pending_handshake(self, id):
        """
        Gets all of the pending handshakes for the user specified by id
        :param id: the id of the user
        :return: SQLAlchemy Cursor
        """
        result = self.session.query(Message.sender_id).filter(
            Message.receiver_id == id,
            Message.sender_ik.isnot(None)
        ).all()
        return result

    def get_messages(self, sender_id, receiver_id):
        """
        Gets all of the messages, in order, between the specified sender and receiver
        :param sender_id: the id of the sender
        :param receiver_id: the id of the receiver
        :return:
        """
        result = self.session.query(Message).filter(or_(and_(
            Message.sender_id == sender_id,
            Message.receiver_id == receiver_id
        ), and_(Message.sender_id == receiver_id,
                Message.receiver_id == sender_id)
        )).order_by(Message.timestamp)
        return [x for x in result]


class UserRepository:
    def __init__(self):
        self.session = session
        self.user = None

    def get_user(self, username, password) -> Login:
        """
        Gets the user with the given username and password
        :param username: the username
        :param password: the password
        :return: Login
        """
        self.user = self.session.query(Login).filter_by(username=username, password=password).first()
        return self.user


    def get_username_by_id(self, id):
        """
        Gets the username for the user with the specified id
        :param id: the id of the user
        :return: SQLAlchemy Cursor
        """
        return self.session.query(Login.id, Login.username).filter(Login.id == id).first()

    def add_user(self, username, password):
        """
        If the given username does not exist, adds the user to the database
        :param username: the username
        :param password: the password
        :return: Login
        """
        new_user = Login(username, password)
        try:
            self.session.add(new_user)
            self.session.commit()
            return new_user
        except IntegrityError:
            print("User already exists")
            self.session.rollback()
            return None
