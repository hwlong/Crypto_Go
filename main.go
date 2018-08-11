package main

import "fmt"

func main(){
	desTest()
	tripleDesTest()
	aesTest()

	RsaTest()

	HashTest()
}

//测试DES加解密
func desTest(){
	fmt.Println("===== des 加解密 =====")
	src := []byte("少壮不努力，老大徙伤悲。")
	key := []byte("12345678")
	str := encryptDES(src, key)
	str = decryptDES(str, key)
	fmt.Println("加解密之后的明文：" + string(str))
}

//测试3DES加解密
func tripleDesTest(){
	fmt.Println("===== 3des 加解密 =====")
	src := []byte("百川东到海，何时复西归。少壮不努力，老大徙伤悲。")
	key := []byte("87654321abcdefgh12345678")
	str := encrypt3DES(src, key)
	str = decrypt3DES(str, key)
	fmt.Println("加解密之后的明文：" + string(str))
}

//测试AES加解密
func aesTest(){
	fmt.Println("===== aes 加解密 =====")
	src := []byte("百川东到海，何时复西归。少壮不努力，老大徙伤悲。")
	key := []byte("87654321abcdefgh")//go只提供了KEY为16字节的接口
	str := encryptAES(src, key)
	str = decryptAES(str, key)
	fmt.Println("加解密之后的明文：" + string(str))
}

func RsaTest(){
	err := RsaGenKey(4096)
	fmt.Println("错误信息：", err)

	//加密
	src := []byte("百川东到海，何时复西归。少壮不努力，老大徙伤悲。")
	data, err := RSAPublicEncrypt(src, []byte("public.pem"))
	//解密
	data, err = RSAPrivateDecrypt(data, "private.pem")
	fmt.Println("RSA非对称加解密之后的明文：" + string(data))
}

//哈希算法测试
func HashTest(){
	data := []byte("百川东到海，何时复西归。少壮不努力，老大徙伤悲。")
	fmt.Println(GetMD5Str_1(data))
	fmt.Println(GetMD5Str_2(data))
}