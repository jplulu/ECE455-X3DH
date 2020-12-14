from datetime import datetime

from sqlalchemy.dialects.mysql import TIMESTAMP
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Integer, Column, ForeignKey, create_engine, BLOB, MetaData
from sqlalchemy.types import Text, JSON, LargeBinary, String
from sqlalchemy.orm import sessionmaker, relationship

# local imports
from src import engine

Base = declarative_base()


class ECPublicKey(Base):
    __tablename__ = "ecpublickeys"

    id = Column(Integer, ForeignKey("logins.id"), primary_key=True)
    ik = Column(LargeBinary)
    spk = Column(LargeBinary)
    spk_sig = Column(LargeBinary)

    opks = relationship('OT_PKey', backref="keybundle", cascade='all,delete')

    def __init__(self, id, ik, spk, spk_sig):
        self.id = id
        self.ik = ik
        self.spk = spk
        self.spk_sig = spk_sig

    def __repr__(self):
        return "<ECPublicKey(id=%s, ik='%s', spk=%s, spk_sig=%s)>" % (
            self.id, self.ik, self.spk, self.spk_sig)


class OT_PKey(Base):
    __tablename__ = "ot_pkeys"

    id = Column(Integer, primary_key=True)
    opk = Column(LargeBinary)

    bundle_id = Column(Integer, ForeignKey('ecpublickeys.id'))

    def __init__(self, opk):
        self.opk = opk

    def __repr__(self):
        return "<OT_PKey(id=%s, bundle_id='%s', opk=%s)>" % (self.id, self.bundle_id, self.opk)


class Message(Base):
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
    engine.execute("DROP DATABASE keybundle;")
    engine.execute("CREATE DATABASE keybundle;")
    engine.execute("USE keybundle;")
    Base.metadata.create_all(engine)
