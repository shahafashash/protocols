from secrets import randbits
from hashlib import sha512


# Diffie-Helman:
#
#                                   Client                       Server
#                                             (3) g^a mod p
# (1) generate random secret (a)      |    -------------------->   |     (4) generate random secret (b)                       
# (2) generate public key   (g^a)     |                            |     (5) generate public key   (g^b)  
#                                     |       (6) g^b mod p        |
#                                     |    <--------------------   |     
# (7) calculate shared key  (g^ab)    |                            |     (7) calculate shared key  (g^ab)
#
#
#
# Example via code: (default 2048bit prime number)
#
#                                                               Client                        Server
#                                                                         (3) client_pkey 
# (1) client = DiffieHellman()                                    |     -------------------->   |     (4) server = DiffieHellman()                      
# (2) client_pkey = client.public_key                             |                             |     (5) server_pkey = server.public_key
#                                                                 |       (6) server_pkey       |
#                                                                 |     <--------------------   |     
# (7) shared_dhkey = client.generate_shared_dhkey(server_pkey)    |                             |     (7) shared_dhkey = server.generate_shared_dhkey(client_pkey)     
#
#
#
# General info:
# primes, groups and generators taken from https://datatracker.ietf.org/doc/rfc3526/?include_text=1
# More Modular Exponential (MODP) Diffie-Hellman groups for Internet Key Exchange (IKE)



primes = {

	# 1536-bit
	5: { 
	"prime": 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF,
	"generator": 2
	},

	# 2048-bit
	14: {
	"prime": 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF,
	"generator": 2
	},

	# 3072-bit 
	15: {
	"prime": 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF,
	"generator": 2
	},

	# 4096-bit
	16: {
	"prime": 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF,
	"generator": 2
	},

	# 6144-bit
	17: {
	"prime": 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AACC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DCC4024FFFFFFFFFFFFFFFF,
	"generator": 2
	},

	# 8192-bit
	18: {
	"prime": 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AACC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DBE115974A3926F12FEE5E438777CB6A932DF8CD8BEC4D073B931BA3BC832B68D9DD300741FA7BF8AFC47ED2576F6936BA424663AAB639C5AE4F5683423B4742BF1C978238F16CBE39D652DE3FDB8BEFC848AD922222E04A4037C0713EB57A81A23F0C73473FC646CEA306B4BCBC8862F8385DDFA9D4B7FA2C087E879683303ED5BDD3A062B3CF5B3A278A66D2A13F83F44F82DDF310EE074AB6A364597E899A0255DC164F31CC50846851DF9AB48195DED7EA1B1D510BD7EE74D73FAF36BC31ECFA268359046F4EB879F924009438B481C6CD7889A002ED5EE382BC9190DA6FC026E479558E4475677E9AA9E3050E2765694DFC81F56E880B96E7160C980DD98EDD3DFFFFFFFFFFFFFFFFF,
	"generator": 2
	}
}

class DiffieHellman:
    """Class to represent a side (client or server) is the key exchange protocol"""
    def __init__(self, group=14) -> None:
        """Instantiate a side in the protocol.

        Args:
            group (int, optional): Group of the prime number. Defaults to 14.
                                   Groups:
                                        5  - 1536bit prime
                                        14 - 2048bit prime
                                        15 - 3072bit prime
                                        16 - 4096bit prime
                                        17 - 6144bit prime
                                        18 - 8192bit prime

        Raises:
            ValueError: If the group given is not supported.
        """
        groups = primes.keys()
        if group in groups:
            self.__prime = primes[group]['prime']
            self.__generator = primes[group]['generator']
            self.__a = randbits(256)                                     # secret private key - 256bit random number
            
        else:
            raise ValueError(f"Group not supported: {group}")

    @property
    def a(self) -> int:
        """Returns the secret private key

        Returns:
            int: Secret private key
        """
        return self.__a

    @property
    def prime(self) -> int:
        """Returns the prime number

        Returns:
            int: Prime number
        """
        return self.__prime

    @property
    def generator(self) -> int:
        """Returns the generator

        Returns:
            int: Generator
        """
        self.__generator

    @property
    def public_key(self) -> int:
        """Returns the public key: (g^a)mod(p)

        Returns:
            int: Public key
        """
        public_key = pow(self.__generator, self.__a, self.__prime)
        return public_key

    def check_other_public_key(self, pub_key: int) -> bool:
        """Checking if the public key given by the other side of the protocol
        is valid based on NIST SP800-56 and Lagrange for safe primes

        Args:
            pub_key (int): Public key of the other side of the protocol: (g^b)mod(p)

        Returns:
            bool: True if the public key stands in the given standards, False otherwise
        """

        # x = pub_key = g^b
        # Checking if 2 < x < prime - 2
        if pub_key > 2 and pub_key < self.__prime - 2:
            # Lagrange for safe primes: q = (prime -1) / 2, x = g^b
            # Checking if x^q == 1:
            #   if True, public key is ok
            #   else, bad public key
            q = (self.__prime - 1) // 2               # ignore numbers after floating point
            if pow(pub_key, q, self.__prime) == 1:
                return True
            else:
                return False

        else:
            return False

    def generate_shared_dhkey(self, pub_key: int) -> str:
        """Checks if the given public key is valid and calculates the shared diffie-hellman key

        Args:
            pub_key (int): Public key of the other side of the protocol: (g^b)mod(p)

        Returns:
            str: Shared diffie-hellman key

        Raises:
            ValueError: If the given public key does not pass the validity check
        """
        # checking validity of the given public key
        validity = self.check_other_public_key(pub_key)
        if validity == False:
            raise ValueError('Given public key is not valid.')
        
        # passed validity check
        # calculating shared key: ((g^b)^a)mod(p) = (g^ab)mod(p)
        _shared_dhkey = pow(pub_key, self.__a, self.__prime)

        # using sha512 to hash the key
        shared_dhkey = sha512(str(_shared_dhkey).encode()).hexdigest()
        return shared_dhkey

# Running example for each prime size with time measurements
if __name__ == '__main__':
    from time import time

    groups = list(primes.keys())
    print('\n')
    for group in groups:
        print('='*150)
        print(f'[*] Group: {group}')

        start_private_key = time()
        client = DiffieHellman(group)
        end_private_key = time()
        first_measurement = end_private_key - start_private_key
        print(f'[*] Client private key: {client.a}')

        start_private_key = time()
        server = DiffieHellman(group)
        end_private_key = time()
        second_measurement = end_private_key - start_private_key
        print(f'[*] Server private key: {server.a}')
        
        average = (first_measurement + second_measurement) / 2
        print(f'[*] Average time to generate private key: {average} seconds')
        
        start_public_key = time()
        client_pkey = client.public_key
        end_public_key = time()
        first_measurement = end_public_key - start_public_key
        print(f'[*] Client public key:\n\n{client_pkey}\n')

        start_public_key = time()
        server_pkey = server.public_key
        end_public_key = time()
        second_measurement = end_public_key - start_public_key
        print(f'[*] Server public key:\n\n{server_pkey}\n')
        
        average = (first_measurement + second_measurement) / 2
        print(f'[*] Average time to calculate public key: {average} seconds')

        start_shared_key = time()
        client_shared_key = client.generate_shared_dhkey(server_pkey)
        end_shared_key = time()
        first_measurement = end_shared_key - start_shared_key
        print(f'[*] Shared key: {client_shared_key}')

        start_shared_key = time()
        server_shared_key = server.generate_shared_dhkey(client_pkey)
        end_shared_key = time()
        first_measurement = end_shared_key - start_shared_key

        average = (first_measurement + second_measurement) / 2
        print(f'[*] Average time to generate shared key: {average} seconds')

        print('='*150)
        print('\n')