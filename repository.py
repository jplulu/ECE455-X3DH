from __future__ import annotations
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy import Table, Column, Integer, MetaData, LargeBinary, ForeignKey, JSON
from typing import List

from models import ECPublicKey, OT_PKey, Message


# engine = create_engine('sqlite:///keybundle.db', echo=False)
# Session = sessionmaker(bind=engine)
# session = Session()
engine = create_engine('mysql://root:123456@localhost:3306/keybundle')  # connect to server
Session = sessionmaker(bind=engine)
session = Session()


class PublicKeyRepository:
    def __init__(self):
        self.session = session

    def insert_public_key_bundle(self, ec_public_key: ECPublicKey) -> None:
        """
        Inserts the given public key bundle
        :param ec_public_key: a public key bundle
        :return: None
        """
        self.session.add(ec_public_key)
        self.session.commit()

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
        result = self.session.query(ECPublicKey)\
            .filter(ECPublicKey.id == id)\
            .first()
        return result

    def clear_public_key_table(self) -> None:
        """
        clears the ecpublickeys table
        :return: None
        """
        self.session.query(ECPublicKey)\
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
        :param id: the bundle_id
        :return: A single OT_PKey
        """
        result = self.session.query(OT_PKey)\
            .filter(OT_PKey.bundle_id == bundle_id)\
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
        self.session.query(OT_PKey)\
            .filter(OT_PKey.id == id)\
            .delete(synchronize_session=False)
        self.session.commit()


class MessageRepository:
    def __init__(self):
        self.session = session

    def insert_message(self, message: Message) -> None:
        self.session.add(message)
        self.session.commit()

    def get_messages_by_receiver_id(self, receiver_id: int) -> Message:
        result = self.session.query(Message)\
            .filter(Message.receiver_id == receiver_id)\
            .first()
        return result

    def get_messages_by_sender_id(self, sender_id: int) -> List[Message]:
        result = self.session.query(Message)\
            .filter(Message.sender_id == sender_id)
        return [x for x in result]



def create_tables(meta, engine):
    """
    Creates the three tables
    :param meta: MetaData
    :param engine: SQLAlchemy engine
    :return: None
    """
    ecpublickeys = Table(
        'ecpublickeys', meta,
        Column('id', Integer, primary_key=True),
        Column('ik', LargeBinary),
        Column('spk', LargeBinary),
        Column('spk_sig', LargeBinary)
    )

    ot_pkeys = Table(
        'ot_pkeys', meta,
        Column('id', Integer, primary_key=True),
        Column('opk', LargeBinary),
        Column('bundle_id', Integer, ForeignKey('ecpublickeys.id'))
    )

    messages = Table(
        'messages', meta,
        Column('id', Integer, primary_key=True),
        Column('receiver_id', Integer, ForeignKey("ecpublickeys.id")),
        Column('sender_id', Integer, ForeignKey("ecpublickeys.id")),
        Column('content', JSON)

    )

    meta.create_all(engine)

