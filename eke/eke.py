from sys import path
path.append('../')
from client_server import Client, Server
from secrets import token_hex
from hashlib import sha256
from configparser import ConfigParser
from diffie_hellman.diffie_hellman import DiffieHellman

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
    def __init__(self, host, port, group=14) -> None:
        super().__init__(host=host, port=port)
        
        self.__dh = DiffieHellman(group=group)

        # read the users file
        self.__filename = './users.ini'
        self.__config = ConfigParser(allow_no_value=True)
        self.__config.read(self.filename)

        self.__username = None
        self.__aes_key = None
        self.__user_key = None
