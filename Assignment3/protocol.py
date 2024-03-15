from Crypto.PublicKey import ECC
from Crypto.Protocol.DH import key_agreement
from Crypto.Hash import SHAKE128
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes
from Crypto.Signature import DSS
import base64
import json

class Protocol:
    
    # Initializer (Called from app.py)
    # TODO: MODIFY ARGUMENTS AND LOGIC AS YOU SEEM FIT
    def __init__(self, shared_secret, callback_key = None, callback_send=None):
        # Using ECC Diffe Hellman Key exchange instead of Diffe, relying on API documentation
        self.shared_secret = shared_secret
        self._key = None
        self.static_priv_key = ECC.generate(curve='p256')
        self.ephemeral_priv_key = ECC.generate(curve='p256')
        self.callback_key = callback_key
        self.isConnectionSecure = False 
        self.nonce = None
        self.callback_send = callback_send
        pass


    # Creating the initial message of your protocol (to be send to the other party to bootstrap the protocol)
    # TODO: IMPLEMENT THE LOGIC (MODIFY THE INPUT ARGUMENTS AS YOU SEEM FIT)
    def GetProtocolInitiationMessage(self):
         nonce = get_random_bytes(16)
         self.nonce = nonce
         print("Initiation, send a static and an ephemeral public key to start the convo")
         return {
            "type": "init",
            "nonce": base64.b64encode(nonce).decode('utf-8'),
            "static_public_key": base64.b64encode(self.static_priv_key.public_key().export_key(format='PEM').encode()).decode('utf-8'),
            "ephemeral_public_key": base64.b64encode(self.ephemeral_priv_key.public_key().export_key(format='PEM').encode()).decode('utf-8'),
        }
        # return {"type": "init", "public_key": self.dh.publickey().exportKey()}


    # Checking if a received message is part of your protocol (called from app.py)

    def IsMessagePartOfProtocol(self, message):
        print("checking the message")
        return isinstance(message, dict) and 'type' in message
        # return False

    def sign_message(self, message):
        signer = DSS.new(self.static_priv_key, 'fips-186-3')
        hash_value = SHA256.new(message)
        return signer.sign(hash_value)

    def verify_signature(self, public_key, message, signature):
        verifier = DSS.new(public_key, 'fips-186-3')
        hash_value = SHA256.new(message)
        try:
            verifier.verify(hash_value, signature)
            return True
        except ValueError:
            return False


    # Processing protocol message
    # TODO: IMPLMENET THE LOGIC (CALL SetSessionKey ONCE YOU HAVE THE KEY ESTABLISHED)
    # THROW EXCEPTION IF AUTHENTICATION FAILS
    def ProcessReceivedProtocolMessage(self, message):
        print("begining of Protocol Messages")
        if message['type'] == 'init':
            print("key exchange type")
            # Process the Static Public Key
            self.isConnectionSecure = True
            static_public_key_b64 = message.get('static_public_key', '')
            ephemeral_public_key_b64 = message.get('ephemeral_public_key', '')
            extracted_nonce_b64 = message.get('nonce', '')
            print("key part 1")

            # Convert from base64 to binary
            static_public_key_pem = base64.b64decode(static_public_key_b64)
            ephemeral_public_key_pem = base64.b64decode(ephemeral_public_key_b64)
            extracted_nonce = base64.b64decode(extracted_nonce_b64)
            print("key part 2")
            # Import the keys
            peer_s_pub_key = ECC.import_key(static_public_key_pem)
            peer_e_pub_key = ECC.import_key(ephemeral_public_key_pem)
            print("key part 3")

        if self._key is not None and self.callback_key is not None:
            self.callback_key()

            print("key part 4")
        if peer_s_pub_key and peer_e_pub_key:
            # ECDH key agreement
            # Private key multipled by public peer key
            shared_secret_static = self.static_priv_key.d * peer_s_pub_key.pointQ
            shared_secret_ephemeral = self.ephemeral_priv_key.d * peer_e_pub_key.pointQ
            print("key part 5")
            # Get shared secret from both keys
            shared_secret = shared_secret_static.x.to_bytes() + shared_secret_ephemeral.x.to_bytes()
            session_key = SHAKE128.new(shared_secret).read(32)
            print("key part 6")
            self.SetSessionKey(session_key)
            if self.callback_key:
                self.callback_key()
            print("Key agreement successful")

            response = self.CreateResponseMessage(extracted_nonce)
            print("Response Message Creation successful")
            self.requestSendMessage(response)
            print("Response Message successful")
        elif message['type'] == 'response':
            server_static_pub_key_b64 = message.get('static_public_key', '')
            server_ephemeral_pub_key_b64 = message.get('ephemeral_public_key', '')
            
            # Decode the server's public keys
            server_static_pub_key = ECC.import_key(base64.b64decode(server_static_pub_key_b64))
            server_ephemeral_pub_key = ECC.import_key(base64.b64decode(server_ephemeral_pub_key_b64))
            
            # Generate the shared secrets and derive the session key
            shared_secret_static = self.static_priv_key.d * server_static_pub_key.pointQ
            shared_secret_ephemeral = self.ephemeral_priv_key.d * server_ephemeral_pub_key.pointQ
            
            shared_secret = shared_secret_static.x.to_bytes() + shared_secret_ephemeral.x.to_bytes()
            session_key = SHAKE128.new(shared_secret).read(32)
            
            self.SetSessionKey(session_key)
        else:
            print("Error: Missing keys in the protocol message.")
        
        
        
    # Key Defining Function - Produce the keys heregiven an input
        # if peer_s_pub_key and peer_e_pub_key:
        #     # Key agreement and session key generation
        #     self._key = key_agreement(
        #         s_priv=self.static_priv_key,
        #         static_pub=peer_s_pub_key,
        #         eph_priv=self.ephemeral_priv_key,
        #         eph_pub=peer_e_pub_key,
        #         kdf=lambda x: SHAKE128.new(x).read(32)
        #     )

        #     self.SetSessionKey(self._key)  # Make sure this sets self._key correctly
        #     if self.callback_key:
        #         self.callback_key()
        #     print("was able to get to key agreement")
        # else:
        #     print("Error: Missing keys in the protocol message.")
            

        # pass
        print("got to the end")


    # Setting the key for the current session
    # TODO: MODIFY AS YOU SEEM FIT
    def SetSessionKey(self, key):
        self._key = key
        if self._key:
            self.isConnectionSecure = True 
        pass

    def requestSendMessage(self, message):
        if self.callback_send:
         self.callback_send(message)
    # Encrypting messages
    # TODO: IMPLEMENT ENCRYPTION WITH THE SESSION KEY (ALSO INCLUDE ANY NECESSARY INFO IN THE ENCRYPTED MESSAGE FOR INTEGRITY PROTECTION)
    # RETURN AN ERROR MESSAGE IF INTEGRITY VERITIFCATION OR AUTHENTICATION FAILS

    def EncryptAndProtectMessage(self, plain_text):
        print("encrypting and protecting the message")
        # cipher_text = plain_text
        # return cipher_text
        if self._key is None:
            raise ValueError("Encryption key has not been initialized.")
        AES_key = self._key
        print("encrypting and protecting the message part 2")
        if not isinstance(plain_text, bytes):
            print("encrypting and protecting the message maybe?")
            plain_text = plain_text.encode()
        # Create/ initialize nonce here
        # nonce = get_random_bytes(AES.block_size)
        print("encrypting and protecting the message 3")
        cipher = AES.new(AES_key, AES.MODE_GCM)
        cipher_text, tag = cipher.encrypt_and_digest(plain_text)
        # Do not need to encrypt nonce
        print("encrypting and protecting the message 4")
        return tag + cipher_text
        # return plain_text.encode('utf-8')

    def CreateResponseMessage(self, extracted_nonce):

        new_challenge = get_random_bytes(16)
        sender_id = "Reciever" 

        # Create the response message
        response_message = {
            "encrypted_nonce": base64.b64encode(self.EncryptAndProtectMessage(extracted_nonce)).decode('utf-8'),
            "new_challenge": base64.b64encode(new_challenge).decode('utf-8'),
            "sender_id": sender_id,
        }

        # Encrypt the response message using the session key
        encrypted_response = self.EncryptAndProtectMessage(json.dumps(response_message))

        return {"encrypted_message": encrypted_response, 
                "static_public_key": base64.b64encode(self.static_priv_key.public_key().export_key(format='PEM').encode()).decode('utf-8'),
                "ephemeral_public_key": base64.b64encode(self.ephemeral_priv_key.public_key().export_key(format='PEM').encode()).decode('utf-8'),
                }
    
    # Decrypting and verifying messages
    # TODO: IMPLEMENT DECRYPTION AND INTEGRITY CHECK WITH THE SESSION KEY
    # RETURN AN ERROR MESSAGE IF INTEGRITY VERITIFCATION OR AUTHENTICATION FAILS
    def DecryptAndVerifyMessage(self, cipher_text):
        print("we're decrypting now")
        nonce = cipher_text[:AES.block_size]
        print("we're decrypting now 2")
        tag = cipher_text[AES.block_size:AES.block_size*2]
        print("we're decrypting now 3")

        encrypted = cipher_text[AES.block_size*2:]
        print("we're decrypting now 4")
        cipher = AES.new(self._key, AES.MODE_GCM, nonce=nonce)
        print("we're decrypting now 5")

        try:

            plain_text = cipher.decrypt_and_verify(encrypted, tag)
            return plain_text.decode('utf-8')
        except ValueError as e:
 
            print(f"Error in decrypting and verifying message: {e}")
            raise
        # plain_text = cipher_text
        # return plain_text
