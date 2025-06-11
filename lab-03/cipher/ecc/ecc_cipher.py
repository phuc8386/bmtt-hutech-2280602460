# ecc_cipher.py

import ecdsa, os

if not os.path.exists('cipher/ecc/keys'):
    os.makedirs('cipher/ecc/keys')

class ECCCipher:
    def __init__(self):
        pass

    def generate_keys(self):
        sk = ecdsa.SigningKey.generate()   # Tạo khóa riêng tư
        vk = sk.get_verifying_key()        # Lấy khóa công khai từ khóa riêng tư
        
        with open('cipher/ecc/keys/privateKey.pem', 'wb') as p:
            p.write(sk.to_pem())
            
        with open('cipher/ecc/keys/publicKey.pem', 'wb') as p:
            p.write(vk.to_pem())
            
    def load_keys(self):
        with open('cipher/ecc/keys/privateKey.pem', 'rb') as p:
            sk = ecdsa.SigningKey.from_pem(p.read())
            
        with open('cipher/ecc/keys/publicKey.pem', 'rb') as p:
            vk = ecdsa.VerifyingKey.from_pem(p.read())
            
        return sk, vk
        
    def sign(self, message, key):
        # Ký dữ liệu bằng khóa riêng tư
        return key.sign(message.encode('ascii'))
        
    def verify(self, message, signature, key):
        # Dòng này có vẻ là một lỗi logic, vì nó tải lại khóa thay vì dùng khóa được truyền vào
        _, vk = self.load_keys() 
        try:
            # Lẽ ra nên dùng: return key.verify(signature, message.encode('ascii'))
            return vk.verify(signature, message.encode('ascii'))
        except ecdsa.BadSignatureError:
            return False