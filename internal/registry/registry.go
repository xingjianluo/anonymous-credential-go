// Package registry 保存签发方的签发记录与撤销状态。
//
// 记录中只包含：随机凭证标识（受访问控制的撤销句柄）、标识承诺、
// 策略版本、签发时间戳与撤销标志。绝不保存任何属性明文或属性盐。
// CheckBlinded 通过“挑战盲化”让验证方在不暴露静态标识的情况下完成
// 在线撤销检查，未知/已撤销标识都得到明确的失败结论。
package registry

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"sync"

	"github.com/xingjianluo/anonymous-credential-go/internal/canonical"
	cerr "github.com/xingjianluo/anonymous-credential-go/internal/errors"
)

// Record 是签发方留存的核对记录（无属性明文）。
type Record struct {
	CredID       []byte
	IDCommitment [32]byte
	PolicyVer    uint32
	IssuedAtUnix int64
	Revoked      bool
	// Rev 是该记录的修订版本：0=有效，1=已撤销。
	Rev uint64
}

// BlindedStatus 是供验证方使用的撤销检查应答。
type BlindedStatus struct {
	IDCommitment [32]byte
	Known        bool
	Active       bool
	Revoked      bool
	ObservedSeq  uint64
}

// Registry 是并发安全的签发/撤销登记表。
type Registry struct {
	mu      sync.RWMutex
	records map[string]*Record // key: hex 无关，直接以标识承诺字节串为键
}

// New 创建空登记表。
func New() *Registry {
	return &Registry{records: map[string]*Record{}}
}

// Add 登记一条新凭证；标识承诺重复即拒绝（正常情况下不可能）。
func (r *Registry) Add(rec *Record) error {
	if rec == nil || len(rec.CredID) == 0 {
		return cerr.New(cerr.KindMalformed, "invalid record")
	}
	key := string(rec.IDCommitment[:])
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.records[key]; exists {
		return cerr.New(cerr.KindPolicyViolation, "credential id commitment already registered")
	}
	cp := &Record{
		CredID:       append([]byte(nil), rec.CredID...),
		IDCommitment: rec.IDCommitment,
		PolicyVer:    rec.PolicyVer,
		IssuedAtUnix: rec.IssuedAtUnix,
		Revoked:      rec.Revoked,
	}
	r.records[key] = cp
	return nil
}

// Revoke 按凭证标识秘密撤销凭证；标识未知返回 KindUnknownCredential。
func (r *Registry) Revoke(credID []byte) error {
	commit := canonical.Hash("cred-id-v1", canonical.EncodeBytes(credID))
	r.mu.Lock()
	defer r.mu.Unlock()
	rec, ok := r.records[string(commit[:])]
	if !ok {
		return cerr.New(cerr.KindUnknownCredential, "cannot revoke: credential id is not registered")
	}
	if !rec.Revoked {
		rec.Revoked = true
		rec.Rev++
	}
	return nil
}

// BlindedTag 计算挑战盲化撤销标识：HMAC(CredID, challenge)。
// 该标签按会话挑战变化，不会在不同会话之间形成可关联标识。
func BlindedTag(credID, challenge []byte) [32]byte {
	mac := hmac.New(sha256.New, credID)
	mac.Write(canonical.Domain("revocation-challenge-v1"))
	mac.Write(canonical.EncodeBytes(challenge))
	var out [32]byte
	copy(out[:], mac.Sum(nil))
	return out
}

// CheckBlinded 应答经挑战盲化的撤销查询。
// 登记表遍历全部记录计算 BlindedTag(rec.CredID, challenge) 做匹配；
// 未知标签返回 Known=false，已撤销返回 Revoked=true。
// 线性扫描是本地模拟实现（记录数有限），语义上等价于隐私凭证的
// 在线吊销检查，且不要求验证方知道明文 CredID。
func (r *Registry) CheckBlinded(challenge []byte, blinded [32]byte) (*BlindedStatus, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, rec := range r.records {
		tag := BlindedTag(rec.CredID, challenge)
		if hmac.Equal(tag[:], blinded[:]) {
			return &BlindedStatus{
				IDCommitment: rec.IDCommitment,
				Known:        true,
				Active:       !rec.Revoked,
				Revoked:      rec.Revoked,
				ObservedSeq:  rec.Rev,
			}, nil
		}
	}
	return &BlindedStatus{Known: false}, cerr.New(cerr.KindUnknownCredential, "blinded credential tag is unknown to issuer")
}

// Audit 按标识承诺核对签发记录（返回副本，不含属性明文）。
func (r *Registry) Audit(idCommitment [32]byte) (*Record, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	rec, ok := r.records[string(idCommitment[:])]
	if !ok {
		return nil, cerr.New(cerr.KindUnknownCredential, "no issuance record for id commitment")
	}
	cp := *rec
	cp.CredID = nil // 审计视图不回放撤销句柄
	return &cp, nil
}

// RevokeRevision 返回该凭证撤销后的修订版本（当前为 1）；未撤销
// 返回 (0,false)。与 CheckBlinded 应答里的 ObservedSeq 在同一全序，
// 可用于校验并发“撤销 vs 校验”结论的线性一致性。
func (r *Registry) RevokeRevision(credID []byte) (uint64, bool) {
	commit := canonical.Hash("cred-id-v1", canonical.EncodeBytes(credID))
	r.mu.RLock()
	defer r.mu.RUnlock()
	rec, ok := r.records[string(commit[:])]
	if !ok || !rec.Revoked {
		return 0, false
	}
	return rec.Rev, true
}

// Stats 是登记表的计数快照（供演示与测试）。
type Stats struct {
	Total   int
	Active  int
	Revoked int
}

// Stats 返回当前计数快照，与并发撤销线性一致（单一 RLock 下取值）。
func (r *Registry) Stats() Stats {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s := Stats{Total: len(r.records)}
	for _, rec := range r.records {
		if rec.Revoked {
			s.Revoked++
		} else {
			s.Active++
		}
	}
	return s
}

var _ = bytes.Equal
