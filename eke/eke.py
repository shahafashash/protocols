from sys import path
path.append('../')
from client_server import Client, Server
from secrets import token_bytes, token_hex
from hashlib import sha256
from configparser import ConfigParser
from diffie_hellman.diffie_hellman import DiffieHellman
from hashlib import sha512

# EKE - Encrypted Key Exchange:
#
#                                                       Client                              Server
#                                                       
# (1) generate secret from password       (w=H(pwd))      |  (3) Username, Ew(g^a mod(p))     |                          
# (2) generate Diffie-Hellman key-pair    (a, g^a)        |      ---------------------->      |     (4) generate secret from password       (w=H(pwd))   
#                                                         |                                   |     (5) generate Diffie-Hellman key-pair    (b, g^b)
#                                                         |                                   |     (6) calculate shared Diffie-Hellman key (k=g^ab mod(p))
#                                                         |(8) Ew(g^b mod(p)), Ek(challengeS) |     (7) generate a challenge                (challengeS)
# (9) calculate shared Diffie-Hellman key (k=g^ab mod(p)) |      <----------------------      |     
# (10) generate a challenge               (challengeC)    |(11) Ek(challengeC, challengeS)    | 
#                                                         |      ---------------------->      |     (12) validate challengeS
#                                                         |      (13) Ek(challengeC)          |
# (14) validate challengeC                                |      <----------------------      |
#
#
#
# Example via code:
# Need to finish this section...
#
# General info:
# This is a basic CHAP implementation for educational purposes only.
# The file containing the users information is not secured!



class EKEServer(Server, DiffieHellman):
    """Class to represent the server side of the protocol"""
    def __init__(self, host='127.0.0.1', port=1234, group=14, block_size=256) -> None:
        """Instantiate the client's side of the protocol

        Args:
            host (str, optional): IP or URL address of the server. Defaults to '127.0.0.1'.
            port (int, optional): Port the server will listen to. Defaults to 1234.
            group (int, optional): Group of the prime number. Defaults to 14.
                                   Groups:
                                        5  - 1536bit prime
                                        14 - 2048bit prime
                                        15 - 3072bit prime
                                        16 - 4096bit prime
                                        17 - 6144bit prime
                                        18 - 8192bit prime
            block_size (int, optional): Messages block size in bits (128, 192 or 256). Defaults to 256.

        Raises:
            ValueError: If block size or group are not valid
        """
        super(EKEServer, self).__init__(host=host, port=port, group=group)
        
        valid_sizes = [128, 192, 256]
        if block_size not in valid_sizes:
            raise ValueError(f'Block size is not valid: {block_size}')

        self.__group = group

        # read the users file
        self.__filename = './users.ini'
        self.__config = ConfigParser(allow_no_value=True)
        self.__config.read(self.__filename)

        self.__block_size = block_size
        self.__offset = self._calculate_offset()
        self.__challenge = token_hex(16)

    @property
    def group(self) -> int:
        """Returns the group from which the Diffie-Hellman keys will be generated

        Returns:
            int: Group
        """
        return self.__filename
    
    @property
    def filename(self) -> str:
        """Returns the name of the users file

        Returns:
            str: The name of the users file
        """
        return self.__filename

    @property
    def config(self) -> ConfigParser:
        """Returns the users file object

        Returns:
            ConfigParser: User file object
        """
        return self.__config

    @property
    def challenge(self) -> bytes:
        """Returns the servers challenge

        Returns:
            bytes: Servers challenge
        """
        return self.__challenge

    @property
    def block_size(self) -> int:
        """Returns the block size of the messages the server 
        expects to recive (size in bits)

        Returns:
            int: Block size (128bit, 192bit or 256bit)
        """
        return self.__block_size

    @property
    def offset(self) -> int:
        """Returns the offset from where the message begins in the
        response recived from the user in the handshake process

        Returns:
            int: Offset
        """
        return self.__offset

    def _calculate_offset(self) -> int:
        """Calculates the offset based on the block size

        Returns:
            int: Offset
        """
        offsets = {
            5: {
                128: 704,
                192: 792,
                256: 704
            },
            14: {
                128: 876,
                192: 1048,
                256: 1048
            },
            15: {
                128: 1388,
                192: 1304,
                256: 1388
            },
            16: {
                128: 1728,
                192: 1916,
                256: 1728
            },
            17: {
                128: 2584,
                192: 2584,
                256: 2752
            },
            18: {
                128: 3436,
                192: 3352,
                256: 3436
            }
        }

        offset = offsets[self.__group][self.__block_size]
        return offset

    def _get_client_key(self, message: bytes) -> bytes:
        """Derives client key from his password 

        Args:
            message (bytes): First message of the handshake process (username + Ew(client public key))

        Returns:
            bytes: Clients key
        """
        username = message[:-self.__offset].decode('utf-8')
        password = self.__config[username].get('password')
        key = sha512(password.encode('utf-8')).hexdigest()[:(self.__block_size//8)]
        return key

    def _get_shared_dhkey(self, message: bytes, key: bytes) -> bytes:
        """Decrypts clients public key and calculates shared Diffie-Hellman key

        Args:
            message (bytes): First message of the handshake process (username + Ew(client public key))
            key (bytes): Clients key

        Returns:
            bytes: Shared Diffie-Hellman key
        """
        enc_message = message[self.__offset:]
        client_pub_key = int(self.aes_decrypt_message(enc_message, key, block_size=self.__block_size))
        shared_dhkey = self.generate_shared_dhkey(client_pub_key)[:(self.__block_size//8)].encode('utf-8')
        return shared_dhkey

    def generate_first_handshake_response(self, message: bytes) -> bytes:
        """Generates the first message the server sends in the handshake process

        Args:
            message (bytes): First message recived from the client in the handshake process (username + Ew(client public key))

        Returns:
            bytes: Servers response to clients first message
        """
        key = self._get_client_key(message)
        shared_dhkey = self._get_shared_dhkey(message, key)
        iv = self.aes_generate_iv()

        pub_key_str = str(self.public_key)
        enc_pub_key = self.aes_encrypt_message(pub_key_str, key, iv, block_size=self.__block_size)
        challenge_str = str(self.__challenge)
        enc_challenge = self.aes_encrypt_message(challenge_str, shared_dhkey, iv, block_size=self.__block_size)
        message = (enc_pub_key + enc_challenge).decode('utf-8')
        return message, shared_dhkey

    def validate_response(self, response: bytes, key: bytes) -> bytes:
        """Validates clients response to see if recived the same challenge that 
        was sent by the server, encrypted with the same shared Diffie-Hellman key

        Args:
            response (bytes): Clients response
            key (bytes): Shared Diffie-Hellman key

        Returns:
            bytes: Returns the clients challenge if validation passed, 'None' if not
        """
        challenges = self.aes_decrypt_message(response, key, block_size=self.__block_size)
        offset = len(challenges) // 2
        challenge = challenges[offset:]
        if challenge == self.__challenge:
            client_challenge = challenges[:offset]
        else:
            client_challenge = None
        
        return client_challenge

    def generate_second_handshake_response(self, challenge: bytes, key: bytes) -> bytes:
        """Encrypts clients challenge with the shared Diffie-Hellman key

        Args:
            challenge (bytes): Clients challenge
            key (bytes): Shared Diffie-Hellman key

        Returns:
            bytes: [description]
        """
        challenge_str = str(challenge)
        iv = self.aes_generate_iv()
        enc_challenge = self.aes_encrypt_message(challenge_str, key, iv, block_size=self.__block_size)
        return enc_challenge

    def do_handshake(self) -> bool:
        """Hook function - Handshake before establishing a connection

        Returns:
            bool: 'True' if connection established successfully and 'False' if not 
        """
        message = self.recieve_message()
        
        response, shared_dhkey = self.generate_first_handshake_response(message)
        self.send_message(response)
       
        message = self.recieve_message()
        challenge = self.validate_response(self, message, shared_dhkey)
        if challenge == None:
            return False

        response = self.generate_second_handshake_response(self, challenge, shared_dhkey)
        self.send_message(response)

        return True
        

class EKEClient(Client, DiffieHellman):
    def __init__(self, group=14, block_size=256) -> None:
        super(EKEClient, self).__init__(group=group)
        
        valid_sizes = [128, 192, 256]
        if block_size not in valid_sizes:
            raise ValueError(f'Block size is not valid: {block_size}')
        
        self.__username = input('Username: ')
        self.__block_size = block_size

    def generate_first_handshake_message(self) -> bytes:
        pub_key_str = str(self.public_key)
        key = self.aes_generate_key(pub_key_str, block_size=self.__block_size)
        iv = self.aes_generate_iv()

        enc_pub_key = self.aes_encrypt_message(pub_key_str, key, iv, block_size=self.__block_size)
        message = str(self.__username.encode('utf-8') + enc_pub_key)
        return message

    def do_handshake(self) -> bool:
        """Hook function - Handshake before establishing a connection

        Returns:
            bool: 'True' if handshake established successfully and 'False' if not
        """
        message = self.generate_first_handshake_message()
        self.send_message(message)

        response = self.recieve_message()
        # TODO: Finish the handshake...


if __name__ == '__main__':
    groups = [5, 14, 15, 16, 17, 18]
    block_sizes = [128, 192, 256]
    group = 14
    
    dh = DiffieHellman(group=group)
    message = str(dh.public_key)
    for block_size in block_sizes: 
        server = EKEServer(group=group, block_size=block_size)
        key = server.aes_generate_key('1234', block_size=block_size)
        iv = server.aes_generate_iv()
        challenge_s = token_bytes(16)
        challenge_c = token_bytes(16)
        message = challenge_c + challenge_s
        enc_message = server.aes_encrypt_message(str(message), key, iv, block_size=block_size)
        dec_message = server.aes_decrypt_message(enc_message, key, block_size=block_size)
        challenge_s_dec = dec_message[len(dec_message) // 2:]
        challenge_c_dec = dec_message[:len(dec_message) // 2]

        info = f"""
challenge server:       {challenge_s}
challenge client:       {challenge_c}
block size:             {block_size}
len:                    {len(enc_message)}
challenge server dec:   {challenge_s}
challenge client dec:   {challenge_c}

        """
        print(info)