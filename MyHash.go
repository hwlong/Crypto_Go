package main

import (
	"crypto/md5"
	"encoding/hex"
)

//使用MD5对数据进行哈希运算
func GetMD5Str_1(src []byte) string {
	//1、给哈希算法添加数据
	res := md5.Sum(src)
	//myres := fmt.Sprint("%x", res)
	myres := hex.EncodeToString(res[:])
	return myres
}

func GetMD5Str_2(src []byte) string {
	//1、创建一个哈希接口
	myHash := md5.New()
	//2、添加数据
	//io.WriteString(myHash, string(src))
	myHash.Write(src)
	//3、计算结果
	res := myHash.Sum(nil)
	//4、散列值格式化
	return hex.EncodeToString(res[:])
}