// Package credential 定义凭证主体、签发方 Ed25519 签名与凭证包。
//
// 凭证不携带任何身份标识：被签名的 Body 只承诺属性 Merkle 根、
// 策略版本、模式摘要与签发时间。每一次签发随机生成独立的 CredID
// （撤销标识秘密），因此同一持有者重复申领得到的凭证之间不存在可
// 关联标识。Bundle 仅在签发响应与持有者钱包中出现。
package credential

import (
	"bytes"
	"crypto/ed25519"
	"time"

	"github.com/xingjianluo/anonymous-credential-go/internal/canonical"
	cerr "github.com/xingjianluo/anonymous-credential-go/internal/errors"
	"github.com/xingjianluo/anonymous-credential-go/internal/sys"
)

// Body 是被签发方签名的凭证主体（全部字段公开且被签名绑定）。
type Body struct {
	PolicyVersion uint32
	CommitRoot    [32]byte
	SchemaHash    [32]byte
	IssuedAt      time.Time
}

// Credential 是持有者接收并在证明中原样出示的凭证。
type Credential struct {
	Body      Body
	Signature []byte
}

// IssuerKey 是签发方 Ed25519 密钥对。
type IssuerKey struct {
	Public  ed25519.PublicKey
	Private ed25519.PrivateKey
}

// GenerateKey 用可注入随机源生成签发方密钥。
func GenerateKey(rng sys.Random) (*IssuerKey, error) {
	if rng == nil {
		return nil, cerr.New(cerr.KindMalformed, "nil random source")
	}
	pub, priv, err := ed25519.GenerateKey(rng)
	if err != nil {
		return nil, cerr.Wrap(err, "generate issuer key")
	}
	return &IssuerKey{Public: pub, Private: priv}, nil
}

// BodyBytes 返回凭证主体的规范化字节（签名与验签共用）。
func BodyBytes(b *Body) []byte {
	var ts int64
	if !b.IssuedAt.IsZero() {
		ts = b.IssuedAt.Unix()
	}
	return canonical.Concat(
		canonical.EncodeString("credential-body-v1"),
		canonical.EncodeInt64(int64(b.PolicyVersion)),
		b.CommitRoot[:],
		b.SchemaHash[:],
		canonical.EncodeInt64(ts),
	)
}

// Sign 对凭证主体签名并组装 Credential。
func Sign(k *IssuerKey, b *Body) (*Credential, error) {
	if k == nil || len(k.Private) == 0 {
		return nil, cerr.New(cerr.KindMalformed, "missing issuer private key")
	}
	if b == nil {
		return nil, cerr.New(cerr.KindMalformed, "nil credential body")
	}
	sig := ed25519.Sign(k.Private, BodyBytes(b))
	return &Credential{Body: *b, Signature: append([]byte(nil), sig...)}, nil
}

// Verify 用签发方公钥校验凭证签名。
func Verify(pub ed25519.PublicKey, c *Credential) error {
	if len(pub) != ed25519.PublicKeySize {
		return cerr.New(cerr.KindMalformed, "issuer public key has wrong size %d", len(pub))
	}
	if c == nil || len(c.Signature) != ed25519.SignatureSize {
		return cerr.New(cerr.KindProofTampered, "credential missing or signature has wrong size")
	}
	if !ed25519.Verify(pub, BodyBytes(&c.Body), c.Signature) {
		return cerr.New(cerr.KindProofTampered, "credential signature does not verify")
	}
	return nil
}

// Bundle 是签发方交给持有者的完整凭证包（私密，绝不进入对外证明）。
type Bundle struct {
	Credential    *Credential
	ID            []byte // 随机凭证标识秘密（撤销用）
	IDCommitment  [32]byte
	Salts         map[string][]byte
	Attrs         map[string]any
	PolicyVersion uint32
	SpecNames     []string
}

// IDCommit 计算标识承诺：H_id(CredID)。
func IDCommit(id []byte) [32]byte {
	return canonical.Hash("cred-id-v1", canonical.EncodeBytes(id))
}

// Equal 常量时间比较两个凭证包的凭证主体（主要供测试使用）。
func (b *Bundle) Equal(other *Bundle) bool {
	if b == nil || other == nil {
		return b == other
	}
	return bytes.Equal(b.Credential.Signature, other.Credential.Signature)
}
