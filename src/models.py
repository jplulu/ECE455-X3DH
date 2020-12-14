from datetime import datetime

from sqlalchemy.dialects.mysql import TIMESTAMP
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Integer, Column, ForeignKey, create_engine, BLOB, MetaData
from sqlalchemy.types import Text, JSON, LargeBinary, String
from sqlalchemy.orm import sessionmaker, relationship
from sqlalchemy.exc import OperationalError

# local imports
from src import engine

Base = declarative_base()


class ECPublicKey(Base):
    """
    Class representing a key bundle. Contains a given user's id, public identity key, signed prekey,
    and their prekey signature.
    """
    __tablename__ = "ecpublickeys"

    id = Column(Integer, ForeignKey("logins.id"), primary_key=True)
    ik = Column(LargeBinary)
    spk = Column(LargeBinary)
    spk_sig = Column(LargeBinary)

    opks = relationship('OT_PKey', backref="keybundle", cascade='all,delete')

    def __init__(self, id: int,
                 ik: bytes,
                 spk: bytes,
                 spk_sig: bytes):
        """
        :@param id: the id of the user
        :@param ik: the public identity key of the user
        :@param spk: the user's signed prekey
        :@param spk: the prekey signature

        """
        self.id = id
        self.ik = ik
        self.spk = spk
        self.spk_sig = spk_sig

    def __repr__(self):
        return "<ECPublicKey(id=%s, ik='%s', spk=%s, spk_sig=%s)>" % (
            self.id, self.ik, self.spk, self.spk_sig)


class OT_PKey(Base):
    """
    Class representing a one-time prekey. opk is the one-time prekey. The bundle_id references the id of the user
    who created the one-time prekey. A given user can have many one-time prekeys.
    """
    __tablename__ = "ot_pkeys"

    id = Column(Integer, primary_key=True)
    opk = Column(LargeBinary)

    bundle_id = Column(Integer, ForeignKey('ecpublickeys.id'))

    def __init__(self, opk):
        self.opk = opk

    def __repr__(self):
        return "<OT_PKey(id=%s, bundle_id='%s', opk=%s)>" % (self.id, self.bundle_id, self.opk)


class Message(Base):
    """
    Class representing a message. A given message contains the sender's id, the receiver's id, the timestamp,
    and the message. Messages that are sent to initiate a handshake also have the sender's public identity key, the
    sender's public ephemeral key, and the one-time prekey that was used in the creaetion of the shared key.
    Messages that are sent after the shared key has been derived have the previously listed values set to NULL.

    """
    __tablename__ = "messages"

    id = Column(Integer, primary_key=True)
    receiver_id = Column(Integer, ForeignKey("logins.id"))
    sender_id = Column(Integer, ForeignKey("logins.id"))
    sender_ik = Column(LargeBinary)
    sender_ek = Column(LargeBinary)
    opk_used = Column(LargeBinary)
    message = Column(LargeBinary)
    timestamp = Column('timestamp', TIMESTAMP(timezone=False), nullable=False, default=datetime.now())

    def __repr__(self):
        return "<Message(id=%s, receiver_id='%s', sender_id=%s, sender_ik=%s, sender_ek=%s, message=%s)>" % (
            self.id, self.receiver_id, self.sender_id, self.sender_ik, self.sender_ek, self.message)


class Login(Base):
    """
    Class representing a user.
    """
    __tablename__ = "logins"

    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True)
    password = Column(Text)

    def __init__(self, username, password):
        self.username = username
        self.password = password

    def __repr__(self):
        return "<Login(id=%s, username=%s, password=%s)>" % (self.id, self.username, self.password)


if __name__ == "__main__":
    try:
        engine.execute("DROP DATABASE keybundle;")
    except OperationalError:
        pass
    engine.execute("CREATE DATABASE keybundle;")
    engine.execute("USE keybundle;")
    Base.metadata.create_all(engine)
