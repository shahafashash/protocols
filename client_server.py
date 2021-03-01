from abc import ABCMeta, abstractmethod
from socket import socket, AF_INET, SOCK_STREAM
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Signature.pkcs1_15 import PKCS115_SigScheme
from hashlib import sha512
from pathlib import Path
from secrets import token_bytes
from base64 import b64encode, b64decode

class Client(metaclass=ABCMeta):
    def __init__(self) -> None:
        """Instantiate a client object"""
        self.__conn = None

    @property
    def conn(self) -> socket:
        """Returns the socket representing the connection with the server

        Returns:
            socket: Connection with the server
        """
        return self.__conn

    def connect_to_server(self, host='127.0.0.1', port=1234) -> bool:
        """Connect to server with the given host address on the given port

        Args:
            host (str, optional): IP or URL address of the server. Defaults to '127.0.0.1'.
            port (int, optional): Port the server will listen to. Defaults to 1234.

        Returns:
            bool: 'True' if handshake established successfully and 'False' if not
        """
        s = socket(AF_INET, SOCK_STREAM)
        s.connect((host, port))
        self.__conn = s
        result = self.do_handshake()
        if result == True:
            return True
        else:
            self.__conn = None
            return False

    def send_message(self, message: str) -> None:
        """Send a message to the server

        Args:
            message (str): Message to send to server
        """
        self.__conn.send(message.encode('utf-8'))

    def recieve_message(self) -> str:
        """Recieve a message from the server

        Returns:
            str: Message recived from the server
        """
        message = self.__conn.recv(1024).decode('utf-8')
        return message

    @abstractmethod
    def do_handshake(self) -> bool:
        """Hook function - Handshake before establishing a connection

        Returns:
            bool: 'True' if handshake established successfully and 'False' if not
        """
        # no handshake
        return True

    def recieve_message(self) -> str:
        """Recieve a message from the client

        Returns:
            str: Message recived from the client
        """
        message = self.__conn.recv(1024).decode('utf-8')
        return message

    @abstractmethod
    def do_handshake(self) -> bool:
        """Hook function - Handshake before establishing a connection

        Returns:
            bool: 'True' if connection established successfully and 'False' if not 
        """
        # no handshake
        return True

    def generate_rsa_keys(self, size=2048) -> RSA.RsaKey:
        """Generates RSA keys with a given size

        Args:
            size (int, optional): Size of keys in bits. Defaults to 2048.
                                  Sizes: 1536bit, 2048bit, 3072bit, 4096bit, 6144bit, 8192bit

        Raises:
            ValueError: If given size is not supported

        Returns:
            RSA.RsaKey: Pair of RSA private and public keys
        """
        valid_sizes = [1024, 2048, 3072, 4096, 6144, 8192]
        if size not in valid_sizes:
            raise ValueError(f'Key size is not valid: {size}')
        
        key_pair = RSA.generate(size)
        return key_pair

    def rsa_encrypt_message(self, message: str, pub_key: RSA.RsaKey) -> bytes:
        """Encrypts the given message using RSA

        Args:
            message (str): Message to encrypt
            pub_key (RSA.RsaKey): Public RSA key

        Returns:
            bytes: Encrypted message
        """
        # convert string to bytes
        msg = message.encode('utf-8')
        # encrypt message
        encryptor = PKCS1_OAEP.new(pub_key)
        encrypted = encryptor.encrypt(msg)
        return encrypted

    def rsa_decrypt_message(self, enc_message: bytes, key_pair: RSA.RsaKey) -> str:
        """Decrypts the given message using RSA

        Args:
            enc_message (bytes): Encrypted message
            key_pair (RSA.RsaKey): RSA key pair of private and public keys

        Returns:
            str: Decrypted message
        """
        # decrypt message
        decryptor = PKCS1_OAEP.new(key_pair)
        decrypted = decryptor.decrypt(enc_message)
        # convert bytes to string
        message = decrypted.decode('utf-8')
        return message

    def rsa_sign_message(self, message: bytes, key_pair: RSA.RsaKey) -> bytes:
        """Sign a given message using PKCS#1 standard version 1.5

        Args:
            message (bytes): Message to sign
            key_pair (RSA.RsaKey): RSA key pair of private and public keys

        Returns:
            bytes: Signed message
        """
        hash = sha512(message)
        signer = PKCS115_SigScheme(key_pair)
        signature = signer.sign(hash)
        return signature

    def rsa_verify_signature(self, message: bytes, signature: int, pub_key: RSA.RsaKey) -> bool:
        """Verify message signature using PKCS#1 standard version 1.5

        Args:
            message (bytes): Message to compare
            signature (int): Signed message
            pub_key (RSA.RsaKey): Public RSA key

        Returns:
            bool: 'True' if signature is valid and 'False' it not
        """
        hash = sha512(message)
        verifier = PKCS115_SigScheme(pub_key)
        
        try:
            verifier.verify(hash, signature)
            status = True
        except:
            status = False

        return status

    def rsa_import_key(self, key_file: str) -> RSA.RsaKey:
        """Import RSA key from a given key file

        Args:
            key_file (str): Path to RSA key file

        Raises:
            FileNotFoundError: If file does not exist

        Returns:
            RSA.RsaKey: RSA key pair
        """
        key_file_obj = Path(key_file).resolve()
        if not key_file_obj.exists():
            raise FileNotFoundError(f'File does not exist: {str(key_file_obj)}')

        with key_file_obj.open('r') as f:
            key = RSA.import_key(f.read())

        return key

    def rsa_export_key(self, key_file: str, key: RSA.RsaKey) -> None:
        """Export RSA key to file

        Args:
            key_file (str): Path to RSA key file
            key (RSA.RsaKey): RSA key to export
        """
        key_file_obj = Path(key_file).resolve()
        key_file_obj.parent.mkdir(parents=True, exist_ok=True)
        with key_file_obj.open('wb') as f:
            f.write(key.export_key())

class Server(metaclass=ABCMeta):
    def __init__(self, host='127.0.0.1', port=1234) -> None:
        """Instantiate a server object

        Args:
            host (str, optional): IP or URL address of the server. Defaults to '127.0.0.1'.
            port (int, optional): Port the server will listen to. Defaults to 1234.
        """
        self.__host = host
        self.__port = port
        self.__conn = None

    @property
    def host(self) -> str:
        """Return the servers address (ip or url)

        Returns:
            str: IP address or URL address
        """
        return self.__host

    @property
    def port(self) -> int:
        """Returns the port the server listens to

        Returns:
            int: Port number
        """
        return self.__port

    @property
    def conn(self) -> socket:
        """Returns the socket representing the connection with the client

        Returns:
            socket: Connection with the client
        """
        return self.__conn

    def wait_for_connection(self) -> bool:
        """Blocking method - Waiting for a connection from a client

        Returns:
            bool: 'True' if handshake established successfully and 'False' if not
        """
        with socket(AF_INET, SOCK_STREAM) as s:
            s.bind((self.__host, self.__port))
            s.listen()
            conn, addr = s.accept()
            self.__conn = conn
            print(f'Connected by: {addr}')
            result = self.do_handshake()
        
        if result == True:
            return True
        else:
            self.__conn = None
            return False


    def send_message(self, message: str) -> None:
        """Send a message to the client

        Args:
            message (str): Message to send to client
        """
        self.__conn.send(message.encode('utf-8'))

    def recieve_message(self) -> str:
        """Recieve a message from the client

        Returns:
            str: Message recived from the client
        """
        message = self.__conn.recv(1024).decode('utf-8')
        return message

    @abstractmethod
    def do_handshake(self) -> bool:
        """Hook function - Handshake before establishing a connection

        Returns:
            bool: 'True' if connection established successfully and 'False' if not 
        """
        # no handshake
        return True

    def generate_rsa_keys(self, size=2048) -> RSA.RsaKey:
        """Generates RSA keys with a given size

        Args:
            size (int, optional): Size of keys in bits. Defaults to 2048.
                                  Sizes: 1536bit, 2048bit, 3072bit, 4096bit, 6144bit, 8192bit

        Raises:
            ValueError: If given size is not supported

        Returns:
            RSA.RsaKey: Pair of RSA private and public keys
        """
        valid_sizes = [1024, 2048, 3072, 4096, 6144, 8192]
        if size not in valid_sizes:
            raise ValueError(f'Key size is not valid: {size}')
        
        key_pair = RSA.generate(size)
        return key_pair

    def rsa_encrypt_message(self, message: str, pub_key: RSA.RsaKey) -> bytes:
        """Encrypts the given message using RSA

        Args:
            message (str): Message to encrypt
            pub_key (RSA.RsaKey): Public RSA key

        Returns:
            bytes: Encrypted message
        """
        # convert string to bytes
        msg = message.encode('utf-8')
        # encrypt message
        encryptor = PKCS1_OAEP.new(pub_key)
        encrypted = encryptor.encrypt(msg)
        return encrypted

    def rsa_decrypt_message(self, enc_message: bytes, key_pair: RSA.RsaKey) -> str:
        """Decrypts the given message using RSA

        Args:
            enc_message (bytes): Encrypted message
            key_pair (RSA.RsaKey): RSA key pair of private and public keys

        Returns:
            str: Decrypted message
        """
        # decrypt message
        decryptor = PKCS1_OAEP.new(key_pair)
        decrypted = decryptor.decrypt(enc_message)
        # convert bytes to string
        message = decrypted.decode('utf-8')
        return message

    def rsa_sign_message(self, message: bytes, key_pair: RSA.RsaKey) -> bytes:
        """Sign a given message using PKCS#1 standard version 1.5

        Args:
            message (bytes): Message to sign
            key_pair (RSA.RsaKey): RSA key pair of private and public keys

        Returns:
            bytes: Signed message
        """
        hash = sha512(message)
        signer = PKCS115_SigScheme(key_pair)
        signature = signer.sign(hash)
        return signature

    def rsa_verify_signature(self, message: bytes, signature: int, pub_key: RSA.RsaKey) -> bool:
        """Verify message signature using PKCS#1 standard version 1.5

        Args:
            message (bytes): Message to compare
            signature (int): Signed message
            pub_key (RSA.RsaKey): Public RSA key

        Returns:
            bool: 'True' if signature is valid and 'False' it not
        """
        hash = sha512(message)
        verifier = PKCS115_SigScheme(pub_key)
        
        try:
            verifier.verify(hash, signature)
            status = True
        except:
            status = False

        return status

    def rsa_import_key(self, key_file: str) -> RSA.RsaKey:
        """Import RSA key from a given key file

        Args:
            key_file (str): Path to RSA key file

        Raises:
            FileNotFoundError: If file does not exist

        Returns:
            RSA.RsaKey: RSA key pair
        """
        key_file_obj = Path(key_file).resolve()
        if not key_file_obj.exists():
            raise FileNotFoundError(f'File does not exist: {str(key_file_obj)}')

        with key_file_obj.open('r') as f:
            key = RSA.import_key(f.read())

        return key

    def rsa_export_key(self, key_file: str, key: RSA.RsaKey) -> None:
        """Export RSA key to file

        Args:
            key_file (str): Path to RSA key file
            key (RSA.RsaKey): RSA key to export
        """
        key_file_obj = Path(key_file).resolve()
        key_file_obj.parent.mkdir(parents=True, exist_ok=True)
        with key_file_obj.open('wb') as f:
            f.write(key.export_key())

    def aes_pad_message(self, message: bytes, block_size=256) -> bytes:
        valid_sizes = [128, 192, 256]
        if block_size not in valid_sizes:
            raise ValueError(f'Key size is not valid: {block_size}')

        padding_size = block_size - len(message) % block_size
        padded_msg = message + padding_size * chr(padding_size)
        return padded_msg

    def aes_upad_message(self, padded_msg: bytes) -> bytes:
        message = padded_msg[:-ord(padded_msg[len(padded_msg)-1:])]
        return message

    def aes_generate_iv(self) -> bytes:
        iv = token_bytes(16)
        return iv

    def aes_encrypt_message(self, message: str, key: bytes, iv: bytes, block_size=256) -> bytes:
        valid_sizes = [128, 192, 256]
        if block_size not in valid_sizes:
            raise ValueError(f'Key size is not valid: {block_size}')
        elif len(iv) != 16:
            raise ValueError(f'Invalid IV size: {len(iv)}bytes')

        msg = self.aes_pad_message(message, block_size=block_size)
        msg = msg.encode('utf-8')

        encryptor = AES.new(key, AES.MODE_CBC, iv)
        encrypted = encryptor.encrypt(msg)
        
        enc_message = b64encode(iv + encrypted)
        return enc_message

    def aes_decrypt_message(self, enc_message: bytes, key: bytes, block_size=256) -> str:
        valid_sizes = [128, 192, 256]
        if block_size not in valid_sizes:
            raise ValueError(f'Key size is not valid: {block_size}')

        _enc_message = b64decode(enc_message)
        iv = _enc_message[:16]

        decryptor = AES.new(key, AES.MODE_CBC, iv)
        decrypted = decryptor.decrypt(_enc_message[16:])

        message = self.aes_upad_message(decrypted)
        message = message.decode('utf-8')

        return message
