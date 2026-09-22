// Package canonical 提供确定性的长度前缀编码与 SHA-256 散列。
//
// 所有需要跨进程/跨版本复算的字节序列都必须走这里编码，禁止直接
// fmt.Sprintf 或 gob/json，以免字段歧义或 map 顺序导致根值漂移。
package canonical

import (
	"crypto/sha256"
	"encoding/binary"
)

// 类型标签，保证不同类型不会编出相同字节。
var (
	tagBytes  = []byte{0x01}
	tagString = []byte{0x02}
	tagInt64  = []byte{0x03}
	tagDomain = []byte{0x04}
)

// lengthPrefix 以 4 字节大端长度前缀包裹 b。
func lengthPrefix(b []byte) []byte {
	out := make([]byte, 4+len(b))
	binary.BigEndian.PutUint32(out, uint32(len(b)))
	copy(out[4:], b)
	return out
}

// Concat 以长度前缀方式拼接字节切片，消除拼接歧义。
func Concat(parts ...[]byte) []byte {
	n := 4 * len(parts)
	for _, p := range parts {
		n += len(p)
	}
	out := make([]byte, 0, n)
	for _, p := range parts {
		out = append(out, lengthPrefix(p)...)
	}
	return out
}

// EncodeString 规范化编码字符串：tag + 长度前缀 + UTF-8 字节。
func EncodeString(s string) []byte {
	body := lengthPrefix([]byte(s))
	return Concat(tagString, body)
}

// EncodeInt64 规范化编码整数：tag + 8 字节大端补码。
func EncodeInt64(n int64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(n))
	return Concat(tagInt64, b)
}

// EncodeBytes 规范化编码字节串：tag + 长度前缀 + 数据。
func EncodeBytes(b []byte) []byte {
	return Concat(tagBytes, lengthPrefix(b))
}

// Domain 生成带域分隔标签的字节，用于不同用途的散列隔离。
func Domain(label string) []byte {
	return Concat(tagDomain, EncodeString(label))
}

// Hash 以域分隔方式计算 SHA-256：H(domain || LP(p1) || LP(p2)...)。
// 第一个参数是用途标签（如 "merkle-leaf"），其余为待散列内容。
func Hash(domain string, parts ...[]byte) [32]byte {
	all := make([][]byte, 0, len(parts)+1)
	all = append(all, Domain(domain))
	all = append(all, parts...)
	return sha256.Sum256(Concat(all...))
}
