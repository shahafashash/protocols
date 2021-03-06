from sys import path
path.append('../')
from client_server import Client, Server
from secrets import token_hex
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

        self.__username = None
        self.__aes_key = None
        self.__user_key = None
        self.__block_size = block_size
        self.__challenge = token_hex(16)

    def _get_offset(self) -> int:
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

    #TODO: break to functions
    def do_handshake(self) -> bool:
        message = self.recieve_message()

        offset = self._get_offset()
        enc_message = message[offset:]
        username = message[:-offset].decode('utf-8')

        password = self.__config[username].get('password')
        key = sha512(password.encode('utf-8')).hexdigest()[:(self.__block_size//8)]
        client_pub_key = int(self.aes_decrypt_message(enc_message, key, block_size=self.__block_size))
        shared_dhkey = self.__dh.generate_shared_dhkey(client_pub_key)[:(self.__block_size//8)].encode('utf-8')

        iv = self.aes_generate_iv()
        pub_key_str = str(self.__dh.public_key)
        enc_pub_key = self.aes_encrypt_message(pub_key_str, key, iv)
        challenge_str = str(self.__challenge)
        enc_challenge = self.aes_encrypt_message(challenge_str, shared_dhkey, iv)
        message = enc_pub_key + enc_challenge
        self.send_message(message.decode('utf-8'))

        


if __name__ == '__main__':
    groups = [5, 14, 15, 16, 17, 18]
    block_sizes = [128, 192, 256]
    
    for group in groups:
        dh = DiffieHellman(group=group)
        message = str(dh.public_key)
        for block_size in block_sizes: 
            server = EKEServer(group=group, block_size=block_size)
            key = server.aes_generate_key('1234', block_size=block_size)
            iv = server.aes_generate_iv()
            enc = server.aes_encrypt_message(message, key, iv, block_size=block_size)
            username = 'alice'.encode('utf-8')
            new_message = username + enc
            offset = server._get_offset()
            _username = new_message[:-offset].decode('utf-8')
            info = f"""
{50*'='}
group:      {group}
block size: {block_size}
offset:     {offset}
username:   {_username}
            """
            print(info)

#             info = f"""
# {50*'='}
# group:      {group}
# block size: {block_size}
# length:     {len(new_message)}
#             """
#             print(info)