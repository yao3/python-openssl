import hashlib
import os
import binascii
import rsa
import OpenSSL.crypto
import base64
from OpenSSL.crypto import PKey
from OpenSSL.crypto import TYPE_RSA, FILETYPE_PEM, TYPE_DSA, FILETYPE_ASN1
from OpenSSL.crypto import dump_privatekey, dump_publickey,load_publickey, load_privatekey
from OpenSSL.crypto import sign, verify
from OpenSSL.crypto import X509
from OpenSSL.crypto import load_certificate, dump_certificate
class function:
    #MD5加密返回MD5的十六进制
    def md5(self,clearText, algorithms = "md5"):
        h = hashlib.new(algorithms)
        h.update(bytes(clearText, 'utf8'))
        print(h.hexdigest())

    # sha1哈希，返回sha1的十六进制
    def sha1(self, clearText, algorithms = "sha1"):
        h = hashlib.new(algorithms)
        h.update(bytes(clearText, 'utf8'))
        print(h.hexdigest())

    # sha224哈希，返回sha224的十六进制
    def sha224(self, clearText, algorithms= "sha224"):
        h = hashlib.new(algorithms)
        h.update(bytes(clearText, 'utf8'))
        print(h.hexdigest())

    # sha256哈希，返回sha256的十六进制
    def sha256(self, clearText, algorithms = "sha256"):
        h = hashlib.new(algorithms)
        h.update(bytes(clearText, 'utf8'))
        print(h.hexdigest())

    # sha512哈希，返回sha512的十六进制
    def sha512(self, clearText, algorithms = "sha512" ):
        h = hashlib.new(algorithms)
        h.update(bytes(clearText,'utf8'))
        print(h.hexdigest())

    # pbkdf2_hmac哈希，返回十六进制
    def pbkdf2_hmac(self, clearText, salt, times,  algorithms="sha256"):
        print(binascii.hexlify(hashlib.pbkdf2_hmac(algorithms,bytes(clearText, 'utf8'), bytes(salt, 'utf8'),times)))
    # 生成RSA的公钥和私钥
    # 采用的是OpenSSL提供的API
    def generateKey(self,directory = "D:\\test",bits=1024):
        pk = PKey()
        pk.generate_key(TYPE_RSA, bits)
        with open (directory+'\pubkey.pem', mode='wb') as f:
            f.write(dump_publickey(FILETYPE_PEM, pk))
            f.close()
        with open (directory+'\prikey.pem', mode='wb') as f:
            f.write(dump_privatekey(FILETYPE_PEM, pk))
            f.close()

    #从PEM文件加载公钥
    def loadPublicKey(self,absolutePath):
        pk = PKey()
        pk  = load_publickey(FILETYPE_PEM, open(absolutePath).read())
        return  pk

    # 从PEM文件加载私钥
    def loadPrivateKey(self,absolutePath):
        pk = PKey()
        key  = load_privatekey(FILETYPE_PEM, open(absolutePath).read())
        return key

    # RSA加密采用的是RSA库
    def rsaEncrypt(self, absolutePathWithClearText, absolutePathWithPEM, absolutePathEncryptText):
        publicKey = rsa.PublicKey.load_pkcs1_openssl_pem(open(absolutePathWithPEM, 'rb').read())
        crypto = rsa.encrypt(open(absolutePathWithClearText, 'rb').read(), publicKey)
        with open(absolutePathEncryptText, 'wb') as enFp:
            enFp.write(crypto)

    # RSA解密采用的是RSA库
    def rsaDecrypt(self, absolutePathWithClearText, absolutePathWithPEM, absolutePathEncryptText):
        with open(absolutePathWithPEM, 'rb') as fp:
            priKey = rsa.PrivateKey.load_pkcs1(fp.read())
        cleartText = rsa.decrypt(open(absolutePathEncryptText, 'rb').read(), priKey)
        with open (absolutePathWithClearText, 'wb') as clearFp:
            clearFp.write(cleartText)

    # RSA签名采用的是OpenSSL提供的API
    def signature(self, absolutePathWithText, absolutePathWithPriKey,absolutePathWithSig):
        pk = self.loadPrivateKey(absolutePathWithPriKey)
        signature = sign(pk, open(absolutePathWithText).read(), 'sha256')
        print("签名成功：\n")
        print(base64.b64encode(signature),"\n")
        with open(absolutePathWithSig, 'wb') as SigFp:
            SigFp.write(signature)
            SigFp.close()
        return signature
    # RSA验证采用的是OpenSSL提供的API
    def verifyFunction(self,absolutePathWithText, absolutePathWithPubKey, absolutePathWithSig):
        pk = self.loadPublicKey(absolutePathWithPubKey)
        x509 = X509()
        x509.set_pubkey(pk)
        signature = open(absolutePathWithSig, 'rb').read()
        try:
            if (verify(x509, signature, open(absolutePathWithText).read(), 'sha256') == None):
                print("验证成功")
        except:
            print("验证失败！")
if __name__ == "__main__":
    f = function()
    while True:
        try:
            select = int(input('''请输入选择：
                        \n1：md5 \t 2：sha1 \t 3：sha224
                        \n4：sha256\t5：sha512\t6：pbkdf2_hmac
                        \n7：生成rsa密钥\t8:rsa加密\t9：rsa解密
                        \n10：rsa签名\t11：rsa验证\t12：退出\n
                        '''))
            if select == 1:
                f.md5(input("请输入待hash文本:\n"))
            elif select == 2:
                f.sha1(input("请输入待hash文本:\n"))
            elif select ==3:
                f.sha224(input("请输入待hash文本:\n"))
            elif select == 4:
                f.sha256(input("请输入待hash文本:\n"))
            elif select == 5:
                f.sha512(input("请输入待hash文本:\n"))
            elif select == 6:
                f.pbkdf2_hmac(input("请输入待hash文本:\n"),input("请输入Salt:\n"),int(input("请输入待Times:\n")),input("请输入算法：如：sha256:\n"))
            elif select == 7:
                f.generateKey(input("输入保存目录"),int(input("请输入位数：")))
            elif select == 8:
                f.rsaEncrypt(input("absolutePathWithClearText\n"), input("absolutePathWithPEM\n"), input("absolutePathEncryptText\n"))
            elif select == 9:
                f.rsaDecrypt(input("absolutePathWithClearText\n"), input("absolutePathWithPEM\n"), input("absolutePathEncryptText\n"))
            elif select == 10:
                f.signature(input("absolutePathWithText\n"), input("absolutePathWithPriKey\n"),input("absolutePathWithSig\n"))
            elif select == 11:
                f.verifyFunction(input("absolutePathWithText\n"), input("absolutePathWithPubKey\n"), input("absolutePathWithSig\n"))
            elif select == 12:
                break
        except Exception as e:
            print(e)