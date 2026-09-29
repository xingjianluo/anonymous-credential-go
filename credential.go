package anoncred

import (
	"crypto/sha256"
	"encoding/binary"
	"sort"
	"strconv"
	"time"
)

// Value 是属性的标量取值。
type Value struct {
	Str   string
	Int   int64
	IsInt bool
}

// StringValue 构造字符串属性值。
func StringValue(s string) Value { return Value{Str: s} }

// IntValue 构造整型属性值。
func IntValue(i int64) Value { return Value{Int: i, IsInt: true} }

// Credential 是签发方返回并由持有者保存的完整凭证。
//
// 其中 Salts、AttrValues 属于持有者私密材料；对外出示时仅按需携带。
type Credential struct {
	Signed     SignedCredential  // 签发方签名的公开部分
	Salts      map[string][]byte // 每个属性的承诺盐
	AttrValues map[string]Value  // 持有者保存的属性明文（不会出现在对外证明中）
}

// SignedCredential 是凭证中被签发方签名、可向验证方出示的公开部分。
//
// 注意：CredID 是每次签发随机生成的不可关联标识，但它出现在对外证明中，
// 验证方理论上可在多次出示之间关联同一凭证（模拟实现的已知限制，见 README）。
type SignedCredential struct {
	PolicyName    string `json:"policy_name"`
	PolicyVersion int    `json:"policy_version"`
	CredID        []byte `json:"cred_id"`
	Pseudonym     string `json:"pseudonym"`
	// HolderVerifyKey 为持有者一次性出示公钥，由签发方签入凭证；
	// 持有者必须持有对应私钥才能生成有效证明（凭证绑定到持有者）。
	HolderVerifyKey []byte `json:"holder_verify_key"`
	// SchemaHash 为签发时策略模式的指纹，随主签名一起固定。
	SchemaHash  []byte            `json:"schema_hash"`
	Commitments map[string][]byte `json:"commitments"`
	NotBefore   time.Time         `json:"not_before"`
	ExpiresAt   time.Time         `json:"expires_at"`
	// PredTokens 为针对全部满足谓词预签发的令牌；持有者仅可出示被会话允许者。
	PredTokens map[string]PredicateToken `json:"pred_tokens"`
	Signature  []byte                    `json:"signature"`
}

// PredicateToken 是签发方对“该凭证满足某谓词”的签名令牌。
type PredicateToken struct {
	Name      string      `json:"name"`
	Attr      string      `json:"attr"`
	Op        PredicateOp `json:"op"`
	Threshold int64       `json:"threshold,omitempty"`
	StrValue  string      `json:"str_value,omitempty"`
	Signature []byte      `json:"signature"`
}

// IssuanceRecord 是签发方留存的记录：不含任何属性明文。
type IssuanceRecord struct {
	CredID        []byte
	Pseudonym     string
	PolicyName    string
	PolicyVersion int
	Commitments   map[string][]byte // 仅保留承诺（盐为一次性随机，不可逆）
	// HolderVerifyKey 为签入凭证的持有者一次性出示公钥；
	// 用于在 v2 出示申请时鉴权“凭证持有者本人”，验证方永远看不到它。
	HolderVerifyKey []byte
	// Predicates 为签发时满足并预签发过令牌的谓词名集合（不含属性值）。
	Predicates   []string
	IssuedAt     time.Time
	NotBefore    time.Time
	ExpiresAt    time.Time
	Revoked      bool
	RevokedAt    time.Time
	RevokeReason string
}

// encodeValue 返回属性值的规范编码。
func encodeValue(v Value) []byte {
	if v.IsInt {
		return append([]byte("i:"), []byte(strconv.FormatInt(v.Int, 10))...)
	}
	return append([]byte("s:"), []byte(v.Str)...)
}

// commitment 计算 attrName|salt|value 的承诺：SHA-256("anoncred:commit:v1"|name|salt|value)。
func commitment(attrName string, salt []byte, v Value) []byte {
	h := sha256.New()
	h.Write([]byte("anoncred:commit:v1"))
	h.Write([]byte(attrName))
	h.Write(salt)
	h.Write(encodeValue(v))
	return h.Sum(nil)
}

func writeLengthPrefixed(dst []byte, b []byte) []byte {
	var l [8]byte
	binary.BigEndian.PutUint64(l[:], uint64(len(b)))
	dst = append(dst, l[:]...)
	dst = append(dst, b...)
	return dst
}

func appendInt64(dst []byte, i int64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(i))
	return append(dst, b[:]...)
}

func appendTime(dst []byte, t time.Time) []byte {
	return appendInt64(dst, t.UTC().UnixNano())
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// signPayload 返回凭证主签名的规范摘要输入。
func (c *SignedCredential) signPayload() []byte {
	var b []byte
	b = append(b, []byte("anoncred:cred:v1")...)
	b = writeLengthPrefixed(b, []byte(c.PolicyName))
	b = appendInt64(b, int64(c.PolicyVersion))
	b = writeLengthPrefixed(b, c.CredID)
	b = writeLengthPrefixed(b, []byte(c.Pseudonym))
	b = writeLengthPrefixed(b, c.HolderVerifyKey)
	b = writeLengthPrefixed(b, c.SchemaHash)
	b = appendTime(b, c.NotBefore)
	b = appendTime(b, c.ExpiresAt)
	// 承诺按名称排序后写入（承诺为盐化哈希，不含明文）。
	for _, name := range sortedKeys(c.Commitments) {
		b = writeLengthPrefixed(b, []byte(name))
		b = writeLengthPrefixed(b, c.Commitments[name])
	}
	// 谓词令牌不进入主签名载荷：它们由签发方独立签名并绑定 CredID，
	// 出示时只携带被会话允许的令牌，避免泄露未披露谓词的满足情况。
	return b
}

// predPayload 返回谓词令牌签名的规范摘要输入。
func predPayload(credID []byte, name, attr string, op PredicateOp, threshold int64, strValue string) []byte {
	var b []byte
	b = append(b, []byte("anoncred:pred:v1")...)
	b = writeLengthPrefixed(b, credID)
	b = writeLengthPrefixed(b, []byte(name))
	b = writeLengthPrefixed(b, []byte(attr))
	b = writeLengthPrefixed(b, []byte(string(op)))
	b = appendInt64(b, threshold)
	b = writeLengthPrefixed(b, []byte(strValue))
	return b
}
