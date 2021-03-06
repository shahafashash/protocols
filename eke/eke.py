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



class EKEServer(Server):
    def __init__(self, host='127.0.0.1', port=1234, group=14, block_size=256) -> None:
        super().__init__(host=host, port=port)
        
        valid_sizes = [128, 192, 256]
        if block_size not in valid_sizes:
            raise ValueError(f'Block size is not valid: {block_size}')

        self.__group = group
        self.__dh = DiffieHellman(group=group)

        # read the users file
        self.__filename = './users.ini'
        self.__config = ConfigParser(allow_no_value=True)
        self.__config.read(self.__filename)

        self.__block_size = block_size
        self.__offset = self._calculate_offset()
        self.__challenge = token_hex(16)

    def _calculate_offset(self) -> int:
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
        username = message[:-self.__offset].decode('utf-8')
        password = self.__config[username].get('password')
        key = sha512(password.encode('utf-8')).hexdigest()[:(self.__block_size//8)]
        return key

    def _get_shared_dhkey(self, message: bytes, key: bytes) -> bytes:
        enc_message = message[self.__offset:]
        client_pub_key = int(self.aes_decrypt_message(enc_message, key, block_size=self.__block_size))
        shared_dhkey = self.__dh.generate_shared_dhkey(client_pub_key)[:(self.__block_size//8)].encode('utf-8')
        return shared_dhkey

    def generate_first_response(self, message: bytes) -> bytes:
        key = self._get_client_key(message)
        shared_dhkey = self._get_shared_dhkey(message, key)
        iv = self.aes_generate_iv()

        pub_key_str = str(self.__dh.public_key)
        enc_pub_key = self.aes_encrypt_message(pub_key_str, key, iv)
        challenge_str = str(self.__challenge)
        enc_challenge = self.aes_encrypt_message(challenge_str, shared_dhkey, iv)
        message = (enc_pub_key + enc_challenge).decode('utf-8')
        return message

    def validate_response(self, response: bytes) -> bytes:
        offset = len(response) // 2
        challenge = response[offset:]
        if challenge == self.__challenge:
            client_challenge = response[:offset]
        else:
            client_challenge = None
        
        return client_challenge

    def generate_second_response(self, challenge: bytes, key: bytes) -> bytes:
        challenge_str = str(challenge)
        iv = self.aes_generate_iv()
        enc_challenge = self.aes_encrypt_message(challenge_str, key, iv)
        return enc_challenge

    def do_handshake(self) -> bool:
        message = self.recieve_message()
        
        response = self.generate_first_response(message)
        message = self.recieve_message()

        challenge = self.validate_response(self, message)
        if challenge == None:
            return False

        response = self.generate_second_response(self, challenge)
        self.send_message(response)

        return True
        
        self.send_message(message.decode('utf-8'))

        


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