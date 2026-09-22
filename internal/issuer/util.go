package issuer

import "encoding/hex"

func uitoa(v uint64) string {
	const digits = "0123456789"
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = digits[v%10]
		v /= 10
	}
	return string(buf[i:])
}

func shortHex(b []byte) string {
	h := hex.EncodeToString(b)
	if len(h) > 16 {
		return h[:16]
	}
	return h
}
