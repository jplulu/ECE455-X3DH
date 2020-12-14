# ECE455-X3DH

## Installing Required Packages

To install the packages, run:

```pip install -r requirements.txt```

If you are using Windows, you will run into an issue with install XEdDSA.

To get around the problem, you will have to download MinGW and CMake. MinGW\bin and CMake\bin must be put on your path before you attempt to install again. Next, download the zip file `libsodium-1.0.18-stable-msvc.zip` from the repository. Unzip and take the file `libsodium.dll` from `libsodium\x64\Release\v142\dynamic` and move it to `system32`.

You will also need an active MySQL server running on localhost.

## Running the program

To initiliaze the database, run:

```python -m src.models -u <user> -p <password>```

Where `<user>` is the user for your MySQL connection and `<password>` is the password.

To run the demo program, run:

 ```python run.py -u <user> -p <password>```
