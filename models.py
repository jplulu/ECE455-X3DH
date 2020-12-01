from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Integer, Column, ForeignKey, create_engine
from sqlalchemy.types import Text
from sqlalchemy.orm import sessionmaker, relationship

Base = declarative_base()


class ECPublicKey(Base):
    __tablename__ = "ecpublickeys"

    id = Column(Integer, primary_key=True)
    id_key = Column(Text)
    sign_pkey= Column(Text)
    prekey_sig = Column(Text)

    ot_pkey = relationship('OT_PKey', cascade='all,delete', backref='ecpublickeys')

    def __repr__(self):
        return "<ECPublicKey(id=%s, id_key='%s', sign_pkey=%s, prekey_sig=%s)>" % (self.id, self.id_key, self.sign_pkey, self.prekey_sig)

class OT_PKey(Base):
    __tablename__ = "ot_pkeys"

    id = Column(Integer, primary_key=True)
    uid = Column(Integer, ForeignKey("ecpublickeys.id"))
    ot_pkey = Column(Text)

    def __repr__(self):
        return "<OT_PKey(id=%s, uid='%s', ot_pkey=%s)>" % (self.id, self.uid, self.ot_pkey)


if __name__ == '__main__':

    engine = create_engine(
          'sqlite:///keybundle.db', echo=False)
    conn = engine.connect()
    session = sessionmaker(bind=engine)
    s = session()
    Base.metadata.create_all(engine)

    # TCP Listening loop here

    # if package wants to retrieve info
    user_id = 1 #Take from TCP package
    ot_pkey = s.query(OT_PKey).filter_by(uid=user_id).first()
    One_pkey = None
    if ot_pkey == None:
        prekey = s.query(ECPublicKey).filter_by(id=user_id).first()
        print(prekey.id)
    else:
        One_pkey = ot_pkey.ot_pkey
        s.delete(ot_pkey)
        s.commit()
    # send the otpkey to

    # if package wants to load info

