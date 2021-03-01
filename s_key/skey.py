from sys import path
path.append('../')
from client_server import Client, Server
from secrets import token_hex, choice
from hashlib import sha512
from pathlib import Path
from configparser import ConfigParser


# S/KEY:
#
# Reset Client:
#                                               Client                      Server
# (1) Generate random secret (S)                  |                           | 
# (2) Generate random number (n)                  |     (4) Username, p       |
# (3) Calculate p = H(H(...H(S))) (n times)       |   -------------------->   |     (5) Update i = 0, p' = p for Username                      
#                                                 |                           |     
#
#
# Login:
#                                                      Client                       Server
#                                                                (1) Username
#                                                        |    -------------------->   |                                 
#                                                        |       (3)   i+1            |     (2) Fetch i+1
#                                                        |    <--------------------   |     
#  (4) Calculate p = H(H(...H(S))) (n-(i+1) times)       |       (5)    p             |     
#                                                        |    -------------------->   |     (6) Check if p' == H(p)
#                                                        |  (7) Sucsses | Failure     |         If True - Update i = i+1, p' = p 
#                                                        |    <--------------------   |         If False - Fail  
#                                                        |                            |
#
#
# Example via code (Reset Client):
#
#                                               Client                      Server
# (1)+(2)+(3) client = SKeyClient('alice')        |                           | 
#             p = client.reset_client()           |     (4) alice + p         |
#                                                 |   -------------------->   |     (5) server = SKeyServer()                      
#                                                 |                           |         server.reset_client('alice', p)
#
#
# Example via code (Login):
#
#                                                      Client                       Server
#                                                                (1)   alice
#  (1) client = SKeyClient('alice')                      |    -------------------->   |                                 
#                                                        |       (3)   index          |     (2) server = SKeyServer() 
#                                                        |    <--------------------   |         index = server.get_next_index('alice') 
#  (4) p = client.get_next_password(index)               |       (5)     p            |     
#                                                        |    -------------------->   |     (6) result = server.validate_response(p)
#                                                        |       (7)  result          |         
#                                                        |    <--------------------   |          
#                                                        |                            |
#
#
# General info:
# This is a basic S/KEY implementation for educational purposes only.
# The file containing the users information is not secured!



class SKeyServer(Server):
    """Class to represent the server side of the protocol"""
    def __init__(self, host='127.0.0.1', port=1234) -> None:
        """Instantiate the server's side of the protocol"""
        super().__init__(host=host, port=port)
        # read the users file
        self.__filename = './users.ini'
        self.__config = ConfigParser(allow_no_value=True)
        self.__config.read(self.filename)

        self.__username = None

    @property
    def config(self) -> ConfigParser:
        """Returns the users file object

        Returns:
            ConfigParser: Users file object
        """
        return self.__config

    @property
    def username(self) -> str:
        """Returns the username

        Returns:
            str: Username
        """
        return self.__username

    @property
    def filename(self) -> str:
        """Returns the name of the users file

        Returns:
            str: The name of the users file
        """
        return self.__filename

    def reset_client(self, username: str, p: str) -> None:
        """Reset i=0 and p'=p for the client with the given username.
        This function is being called if the next index to be returned (i+1) equals n
        for the given username.

        Args:
            username (str): Client username
            p (str): n times sha512 over the clients secret

        Raises:
            ValueError: If user does not exist in the system
            ValueError: Function is not sha512 output
        """
        if username == None or type(username) != str:
            raise ValueError(f'Username is not valid: {username}')
        elif not (type(p) == str and len(p) == 128):
            raise ValueError(f'Function recieved is not valid: {p}')
        else:
            if not self.__config.has_section(username):
                self.__config.add_section(username)
                self.__config.set(username, 'i', 0)
                self.__config.set(username, 'p', p)
                with open(self.filename, 'w') as configfile:
                    self.__config.write(configfile)

    def get_next_index(self, username: str) -> int:
        """Returns the number of successfull connections plus one

        Args:
            username (str): Client username

        Raises:
            ValueError: If user does not exist in the system
            ValueError: Function is not sha512 output

        Returns:
            int: Next index (number of successfull connections plus one)
        """
        if username == None or type(username) != str:
            raise ValueError(f'Username is not valid: {username}')
        elif not self.__config.has_section(username):
            raise ValueError(f'Username does not exist: {username}')
        else:
            self.__username = username
            index = self.__config.getint(username, 'i')
            index += 1
            return index

    def validate_response(self, response: str) -> bool:
        """Check if the response is valid by comparing sha512(response) with p saved
        for the user. If equal, updates the users file and returns True.

        Args:
            response (str): H(H(...H(S))) (n-(i+1) times) 

        Raises:
            ValueError: Function is not sha512 output
            Exception: If trying to validate response of a user that is not 
                       currently trying to connect

        Returns:
            bool: 'True' if the response is valid and 'False' if not
        """
        if not (type(response) == str and len(response) == 128):
            raise ValueError(f'Function recieved is not valid: {response}')
        elif self.__username == None:
            raise Exception(f'No username recived')
        else:
            p = self.__config.get(self.__username, 'p')
            next_p = sha512(response.encode('utf-8')).hexdigest()
            # print(next_p)
            if p == next_p:
                self.__config.set(self.__username, 'p', response)
                index = self.__config.getint(self.__username, 'i')
                self.__config.set(self.__username, 'i', str(index+1))
                with open(self.__filename, 'w') as configfile:
                    self.__config.write(configfile)
                self.__username = None
                return True
            else:
                return False

    def do_handshake(self) -> bool:
        """Hook function - Handshake before establishing a connection

        Returns:
            bool: 'True' if handshake established successfully and 'False' if not
        """
        message = self.recieve_message()
        message_size = len(message)
        if message_size > 128:
            # reset required
            # this reset is not safe because the user is not being verified!!!
            password = message[message_size-128:]
            username = message[0:message_size-128]
            self.reset_client(username, password)
            print(f'[*] Client made reset: {username}')
            print('[*] Aborting handshake...')
            # self.conn.close()
            return False
        else:
            username = message
            next_index = self.get_next_index(username)
            # print(next_index)
            message = str(next_index)
            self.send_message(message)
            response = self.recieve_message()
            # print(response)
            status = self.validate_response(response)
            message = 'Success' if status == True else 'Failure'
            self.send_message(message)

            if status == False:
                self.__conn.close()

            return status

class SKeyClient(Client):
    """Class to represent the client side of the protocol"""
    def __init__(self) -> None:
        """Instantiate the client's side of the protocol"""
        self.__config = ConfigParser(allow_no_value=True)
        self.__username = input('Username: ')
        self.__filename = './client.ini'
        self.need_reset = False
        
        self.__config.read(self.filename)
        if not self.__config.has_section(self.__username):
            # add user if does not exist
            print(f'[*] Registering new user: {self.__username}')
            self.__config.add_section(self.__username)
            self.__config[self.__username]['n'] = 0
            self.__config[self.__username]['secret'] = ''
            with open(self.filename, 'w') as configfile:
                self.__config.write(configfile)
            self.need_reset = True
            self.__secret = ''
            self.__n = 0
        else:
            # get user info
            self.__secret = self.__config.get(self.username, 'secret')
            self.__n = self.__config.getint(self.username, 'n')

    @property
    def config(self) -> ConfigParser:
        """Returns the user file object

        Returns:
            ConfigParser: User file object
        """
        return self.__config

    @property
    def username(self) -> str:
        """Returns the username

        Returns:
            str: Username
        """
        return self.__username

    @property
    def filename(self) -> str:
        """Returns the name of the users file

        Returns:
            str: The name of the users file
        """
        return self.__filename

    @property
    def secret(self) -> str:
        """Returns the users secret

        Returns:
            str: 16byte secret
        """
        return self.__secret

    @property
    def n(self) -> int:
        """Returns the users random number n

        Returns:
            int: Max number of successfull connections allowed for user before reset
        """
        return self.__n

    def reset_client(self) -> None:
        """Resets the client max number of successfull connections allowed (n), generates
        a new secret and calculates p0 and sends it to the server.
        """
        print('[*] Client performing a reset')
        secret = token_hex(16)
        n = choice(range(1000, 9999))
        p = secret

        for i in range(n):
            p = sha512(p.encode('utf-8')).hexdigest()
             
        self.__config.set(self.username, 'secret', secret)
        self.__config.set(self.username, 'n', str(n))
        with open(self.filename, 'w') as configfile:
                self.__config.write(configfile)
        
        self.__secret = secret
        self.__n = n

        # send new password to server
        message = self.__username + p
        self.send_message(message)
        self.need_reset = False
        # self.conn.close()
        print('[*] Client reset finished!')

    def get_next_password(self, index: int) -> str:
        """Calculates the password for the current connection

        Args:
            index (int): Index of the current connection

        Raises:
            Exception: If client reset is required

        Returns:
            str: Password for the current connection
        """
        # print(index)
        hashes = self.__n - (int(index))
        delta = choice(range(0, 100))
        # reset the password on random delta
        if hashes <= delta:
            self.reset_client = True
            raise Exception('Client reset required!')
        else:
            p = self.__secret
            for i in range(hashes):
                p = sha512(p.encode('utf-8')).hexdigest()

            # print(p)
            return p

    def do_handshake(self) -> bool:
        """Hook function - Handshake before establishing a connection

        Returns:
            bool: 'True' if handshake established successfully and 'False' if not
        """
        if self.need_reset == True:
            self.reset_client()
            return False
        else:
            self.send_message(self.__username)
            index = self.recieve_message()
            
            try:
                p = self.get_next_password(index)
            except Exception as ex:
                print(ex)
                self.reset_client()
                print('[*] Please reconnect to the server')
                return False
            
            message = p
            self.send_message(message)
            response = self.recieve_message()
            status = True if response == 'Success' else False

            return status