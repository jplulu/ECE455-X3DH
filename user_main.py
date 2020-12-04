from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import  models
from User import User

def LoginRegister(session):
    while (True):

        user = None

        choice = input("(1) Login \n(2) Register\n(3) Exit\n")
        if choice != "1" and choice != "2" and choice != "3":
            print("Incorrect input\n" + 20 * ("-"))
        choice = int(choice)

        if choice == 1:
            username = input("Username: ")
            password = input("Password: ")
            user = s.query(models.Login).filter_by(username=username, password=password).first()
            if (user == None):
                print("User does not exist.\n" + 20 * ("-"))
                continue
            else:
                print(20 * ("-"))
                return user
        elif choice == 2:
            while (True):
                username = input("Username: ")
                password = input("Password: ")
                if (s.query(models.Login).filter_by(username=username).first() == None):
                    account = models.Login(username=username, password=password)
                    account.keybundle = account.id
                    s.add(models.Login(username=username, password=password))
                    s.commit()
                    print("User created.\n" + 20 * ("-"))
                    return
            else:
                    print("Username taken.\n" + 20 * ("-"))
                    usrinput = input("Do you wish to try again?\n(1) Yes\n(2) No\n")
                    if usrinput == "1":
                        continue
                    if usrinput == "2":
                        break
        else:
            return



if __name__ == '__main__':

    engine = create_engine(('mysql+pymysql:///keybundle'))
    conn = engine.connect()
    session = sessionmaker(bind=engine)
    s = session()
    login_info = None

    while(True):

        login_info = LoginRegister(s)
        if (login_info == None):
            exit(3)

        user = User(login_info)
        while(True):
            # user.load_keys(str(login_info.username) + ".txt")
            user.publish_keys(opk_count=0)
            # user.save_keys(str(login_info.username) + ".txt")
            exit()


