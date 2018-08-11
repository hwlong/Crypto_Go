package main

import (
	"crypto/rsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
)

/**
	生成私钥
	1、使用rsa中的GenerateKey方法生成私钥
	2、通过x509标准将得到的ras私钥序列化为ASN.1的DER编码字符串
	3、将私钥字符串设置到pem格式块中
	4、通过pem将设置好的数据进行编码，并写入磁盘文件中

	生成公钥
	1、从得到的私钥对象中将公钥信息取出
	2、通过x509标准将得到的ras公钥序列化为字符串
	3、将公钥字符串设置到pem格式块中
	4、通过pem将设置好的数据进行编码，并写入磁盘文件中
 */
 func RsaGenKey(bits int) error {
 	privKey, err := rsa.GenerateKey(rand.Reader, bits)
 	if err != nil {
 		return err
	}
 	privStream := x509.MarshalPKCS1PrivateKey(privKey)
 	block := pem.Block{
 		Type:"RSA Private Key",
 		Bytes:privStream,
	}
 	privFile, err := os.Create("private.pem")
	 if err != nil {
		 return err
	 }
	 defer privFile.Close()
 	err = pem.Encode(privFile, &block)
	 if err != nil {
		 return err
	 }


 	pubKey := privKey.PublicKey
 	pubStream, err:= x509.MarshalPKIXPublicKey(&pubKey)//只支持RSA或ECDSA
	 if err != nil {
		 return err
	 }
 	block = pem.Block{
 		Type:"RSA Public Key",
 		Bytes:pubStream,
	}
	 pubFile, err := os.Create("public.pem")
	 if err != nil {
		 return err
	 }
	 err = pem.Encode(pubFile, &block)
	 if err != nil {
		 return err
	 }
	 pubFile.Close()

 	return nil
 }


/**
	使用RSA公钥加密
	1、将公钥文件中的公角读出，得到使用pem编码的字符串
	2、将得到的字符串解码
	3、使用x509将编码之后的公钥解析出来
	4、使用得到的公钥通过rsa进行数据加密

	私钥解密
	1、将私钥文件中的私钥读出，得到使用pem编码的字符串
	2、将得到的字符串解码
	3、使用x509将编码之后的私钥解析出来
	4、使用得到的私钥通过rsa进行数据解密
 */
func RSAPublicEncrypt(src, pathname []byte) ([]byte, error) {
	msg := []byte("")
	file, err := os.Open(string(pathname))
	if err != nil {
		return msg, err
	}
	info, err := file.Stat()
	if err != nil {
		return msg, err
	}
	recvBuf := make([]byte, info.Size())
	file.Read(recvBuf)
	block, _ := pem.Decode(recvBuf)
	pubIKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return msg, err
	}
	pubKey := pubIKey.(*rsa.PublicKey)
	msg, err = rsa.EncryptPKCS1v15(rand.Reader, pubKey, src)
	if err != nil {
		return msg, err
	}

	return msg, nil
}

//私钥解密
func RSAPrivateDecrypt(src []byte, pathname string) ([]byte, error) {
	msg := []byte("")
	file, err := os.Open(pathname)
	if err != nil {
		return msg, err
	}
	info, err := file.Stat()
	if err != nil {
		return msg, err
	}
	recvBuf := make([]byte, info.Size())
	file.Read(recvBuf)
	block, _ := pem.Decode(recvBuf)
	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return msg, err
	}
	msg, err = rsa.DecryptPKCS1v15(rand.Reader, privKey, src)
	if err != nil {
		return msg, err
	}

	return msg, nil
}