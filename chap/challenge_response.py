from sys import path
path.append('../')
from client_server import Client, Server
from secrets import token_hex
from hashlib import sha256
from configparser import ConfigParser
from getpass import getpass

# CHAP - Challenge Handshake Authentication Protocol:
#
#                                               Client                       Server
#                                                         (2) Challenge
#                                                 |    <--------------------   |     (1) generate random challenge                       
# (3) generate response (H(challenge, password))  |                            |       
#                                                 |  (4) Username, Response    |
#                                                 |    -------------------->   |     
#                                                 |                            |     (5) check the response
#                                                 |  (6) Sucsses | Failure     |     
#                                                 |    <--------------------   | 
#
#
#
# Example via code:
#
#                                               Client                       Server
#                                                         (2) challenge
#                                                 |    <--------------------   |     (1) server = CHAPServer()
#                                                 |                            |         challenge = server.challenge                       
# (3) client = CHAPClient('alice', '1am4l1c3!')   |                            |
#     response = client.create_response(challenge)|                            |
#     msg = username + response                   |                            |       
#                                                 |         (4) msg            |
#                                                 |    -------------------->   |     
#                                                 |                            |     (5) result = server.check_response(msg)
#                                                 |         (6) result         |     
#                                                 |    <--------------------   | 
#
#
#
# General info:
# This is a basic CHAP implementation for educational purposes only.
# The file containing the users information is not secured!

class CHAPServer(Server):
    """Class to represent the server side of the protocol"""
    def __init__(self, host='127.0.0.1', port=1234) -> None:
        """Instantiate the server's side of the protocol"""
        super().__init__(host=host, port=port)
        # generate a random challenge
        self.__challenge = token_hex(16)
        
        # read the users file
        self.__config = ConfigParser()
        self.__config.read('./users.ini')

    @property
    def challenge(self) -> str:
        """Returns the challenge

        Returns:
            str: 16Byte challenge
        """
        return self.__challenge

    @property
    def config(self) -> ConfigParser:
        """Returns the users file object

        Returns:
            ConfigParser: Users file object
        """
        return self.__config

    def do_handshake(self) -> bool:
        """Handshake before establishing a connection

        Returns:
            bool: 'True' if connection established successfully and 'False' if not 
        """
        # send challenge
        self.send_message(self.__challenge)
        # recive username and response for challenge
        message = self.recieve_message()
        # check the response and send back the result
        result = self.check_response(message)
        message = 'Success' if result == True else 'Failure'
        self.send_message(message)

        if result == False:
            self.__conn.close()

        return result

    def check_response(self, message: str) -> bool:
        """Check if the given response is valid.
        If the user does not exists or the given the response does not equal to the
        hased challenge and password, the check will fail.

        Args:
            message (str): Username + SHA256(Challenge, Password)

        Returns:
            bool: 'True' if got valid username, password and challenge, 'False' otherwise.
        """
        message_size = len(message)
        # get the username and the response from the message
        response = message[message_size-64:]
        username = message[0:message_size-64]

        # check if the user exists in the system
        user_exists = self.__config.has_option('USERS', username)
        if user_exists == False:
            return False
        
        # get the user's password from the passwords file
        password = self.__config['USERS'][username]
        # generate expected response
        expected_response = sha256(str(self.__challenge + password).encode('utf-8')).hexdigest()
        # check if the got the expected response from the client
        if response != expected_response:
            return False
        else:
            return True

class CHAPClient(Client):
    """Class to represent the client side of the protocol"""
    def __init__(self) -> None:
        """Instantiate the client's side of the protocol

        Args:
            username (str): Username
            password (str): Password
        """
        super().__init__()

        self.__username = input('Username: ')

    @property
    def username(self) -> str:
        """Returns the username

        Returns:
            str: Username
        """
        return self.__username

    def create_response(self, challenge: str) -> str:
        """Creates a response based on the given challenge and user's password.

        Args:
            challenge (str): Challenge recived from the server.

        Returns:
            str: Response to send to the server: Username + SHA256(Challenge, Password)
        """
        password = getpass()
        hashed_data = sha256(str(challenge + password).encode('utf-8')).hexdigest()
        response = self.__username + hashed_data
        return response

    def do_handshake(self) -> bool:
        """Handshake before establishing a connection

        Returns:
            bool: 'True' if handshake established successfully and 'False' if not
        """
        challenge = self.recieve_message()
        message = self.create_response(challenge)
        self.send_message(message)
        result = self.recieve_message()
        status = True if result == 'Success' else False

        return status
    
