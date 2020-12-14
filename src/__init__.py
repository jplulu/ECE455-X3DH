import sys
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.exc import OperationalError


argv = sys.argv

Base = declarative_base()



if "-p" in argv and "-u" in argv:
    user = argv[argv.index("-u")+1]
    password = argv[argv.index("-p")+1]
    engine = create_engine('mysql://{}:{}@localhost/keybundle'.format(user, password))  # connect to server
    try:
        engine.connect()
    except OperationalError:
        print("Invalid user and password.")
        exit(-1)



else:
    print("Invalid command line arguments.")
    exit(-1)











