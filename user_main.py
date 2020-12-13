from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import models
from repository import UserRepository
from User import User

user_repo = UserRepository()


def LoginRegister():
    while True:
        choice = input("(1) Login \n(2) Register\n(3) Exit\n")
        if choice != "1" and choice != "2" and choice != "3":
            print("Incorrect input\n" + 20 * "-")
        choice = int(choice)

        if choice == 1:  # Login
            username = input("Username: ")
            password = input("Password: ")
            user = user_repo.get_user(username, password)
            if user is None:
                print("User does not exist.\n" + 20 * "-")
                continue
            else:
                user = User(user)
                while True:
                    bundle = input("Keybundle filename: ")
                    try:
                        user.load_keys(bundle)
                        break
                    except:
                        print("Invalid file.")
                        continue
                logged_in(user, bundle)
        elif choice == 2:  # Register
            while True:
                username = input("Username: ")
                password = input("Password: ")
                if username is None or password is None:
                    print("Username or password empty.")
                    continue
                new_user = user_repo.add_user(username, password)
                if new_user is None:
                    break
                user = User(new_user)
                user.set_keys()
                user.publish_keys(5)
                key_filename = input("Saved keys filename: ")
                user.save_keys(key_filename)
                logged_in(user, key_filename)
                break
        else:
            return


def logged_in(user, key_filename=None):
    print(20 * "-")
    while True:
        choice = input(
            "(1) Initiate Handshake \n(2) Get Pending Handshake\n(3) Complete Handshake\n(4) Send Message\n(5) Read "
            "Messages\n(6) Log out\n")
        if choice == '1':
            while True:
                receiver = input("Receiver id: ")
                if receiver.isdigit():
                    break
                else:
                    print("Invalid id input")
            user.initiate_handshake(int(receiver))
            user.save_keys(key_filename)
        elif choice == '2':
            pending_handshakes = user.message_repository.get_pending_handshake(user.login.id)
            if not pending_handshakes:
                print("No pending handshakes.")
            else:
                for h in pending_handshakes:
                    print([x for x in user_repo.get_username_by_id(h[0])])
        elif choice == '3':
            while True:
                id = input("User id to complete handshake with: ")
                if id.isdigit():
                    break
                else:
                    print("Invalid id input")
            user.complete_handshake(id=int(id))
            user.save_keys(key_filename)
        elif choice == '4':
            while True:
                id = input("Receiver id: ")
                if id.isdigit():
                    break
                else:
                    print("Invalid id input")
            input_message = input("Message: ")
            user.send_message(int(id), input_message)
        elif choice == '5':
            while True:
                sender_id = input("Sender id: ")
                receiver_id = input("Receiver id: ")
                if sender_id.isdigit() and (receiver_id == '' or receiver_id.isdigit()):
                    break
                else:
                    print("Invalid id input")
            user.get_message_by_sender(int(sender_id), receiver_id)
        elif choice == '6':
            user.save_keys(key_filename)
            break
        else:
            print("Invalid Choice")


if __name__ == '__main__':
    LoginRegister()
