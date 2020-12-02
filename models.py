from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Integer, Column, ForeignKey, create_engine, BLOB
from sqlalchemy.types import Text, JSON, LargeBinary
from sqlalchemy.orm import sessionmaker, relationship

Base = declarative_base()


class ECPublicKey(Base):
    __tablename__ = "ecpublickeys"

    id = Column(Integer, primary_key=True)
    ik = Column(LargeBinary)
    spk = Column(LargeBinary)
    spk_sig = Column(LargeBinary)

    opks = relationship('OT_PKey', cascade='all,delete')

    def __init__(self, ik, spk, spk_sig):
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
    receiver_id = Column(Integer, ForeignKey("ecpublickeys.id"))
    sender_id = Column(Integer, ForeignKey("ecpublickeys.id"))
    content = Column(JSON)

    def __repr__(self):
        return "<Message(id=%s, receiver_id='%s', sender_id=%s, content=%s)>" % (
            self.id, self.receiver_id, self.sender_id, self.content)
