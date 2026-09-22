// Package issuer 实现签发方：申请策略校验、凭证签发、撤销与审计。
//
// 签发流程：
//  1. 策略注册表校验申请（缺失/越界/一致性，废止版本拒绝）；
//  2. 每个属性生成随机盐，构造 Merkle 承诺；
//  3. 随机生成全新 CredID（同一持有者重复申领不可关联）；
//  4. 对 Body 签名，登记表只写入标识承诺/版本/时间/撤销标志，
//     属性明文与盐都不落盘记录。
package issuer

import (
	"github.com/xingjianluo/anonymous-credential-go/internal/commitment"
	"github.com/xingjianluo/anonymous-credential-go/internal/credential"
	cerr "github.com/xingjianluo/anonymous-credential-go/internal/errors"
	"github.com/xingjianluo/anonymous-credential-go/internal/logging"
	"github.com/xingjianluo/anonymous-credential-go/internal/policy"
	"github.com/xingjianluo/anonymous-credential-go/internal/registry"
	"github.com/xingjianluo/anonymous-credential-go/internal/sys"
)

const saltLen = 32
const credIDLen = 32

// Issuer 是凭证签发方。
type Issuer struct {
	key    *credential.IssuerKey
	polreg *policy.Registry
	reg    *registry.Registry
	clock  sys.Clock
	rng    sys.Random
	log    logging.Logger
}

// New 构造签发方。
func New(key *credential.IssuerKey, polreg *policy.Registry, reg *registry.Registry, clock sys.Clock, rng sys.Random, log logging.Logger) *Issuer {
	return &Issuer{key: key, polreg: polreg, reg: reg, clock: clock, rng: rng, log: log}
}

func (i *Issuer) emit(sessionID string, fields map[string]string, msg string) {
	if i.log != nil {
		i.log.Log(sessionID, fields, msg)
	}
}

// Issue 校验申请并签发凭证包；登记记录中不含明文属性。
func (i *Issuer) Issue(req *policy.IssuanceRequest) (*credential.Bundle, error) {
	sessionID := "issue:" + anonLabel(req)
	pol, err := i.polreg.ValidateIssuance(req)
	if err != nil {
		i.emit(sessionID, map[string]string{
			"decision": "reject",
			"basis":    "policy_validation",
			"error":    cerr.KindOf(err).String(),
		}, "issuance rejected")
		return nil, err
	}

	names := pol.AttrNames()
	salted := make([]commitment.SaltedAttr, 0, len(names))
	salts := make(map[string][]byte, len(names))
	values := make(map[string]any, len(req.Attrs))
	for _, n := range names {
		v, present := req.Attrs[n]
		if !present {
			salted = append(salted, commitment.SaltedAttr{Name: n, Missing: true})
			continue
		}
		salt := make([]byte, saltLen)
		if _, err := i.rng.Read(salt); err != nil {
			return nil, cerr.Wrap(err, "generate salt")
		}
		salted = append(salted, commitment.SaltedAttr{Name: n, Value: v, Salt: salt})
		salts[n] = salt
		values[n] = v
	}
	tree, err := commitment.Build(names, salted)
	if err != nil {
		return nil, err
	}
	root := tree.Root()
	schema := pol.SchemaHash()
	now := i.clock.Now()
	body := &credential.Body{
		PolicyVersion: pol.Version,
		CommitRoot:    root,
		SchemaHash:    schema,
		IssuedAt:      now,
	}
	cred, err := credential.Sign(i.key, body)
	if err != nil {
		return nil, err
	}

	id := make([]byte, credIDLen)
	if _, err := i.rng.Read(id); err != nil {
		return nil, cerr.Wrap(err, "generate credential id")
	}
	idCommit := credential.IDCommit(id)

	if err := i.reg.Add(&registry.Record{
		CredID:       id,
		IDCommitment: idCommit,
		PolicyVer:    pol.Version,
		IssuedAtUnix: now.Unix(),
	}); err != nil {
		return nil, err
	}

	i.emit(sessionID, map[string]string{
		"decision":  "accept",
		"basis":     "signature_and_registration",
		"policy_v":  uitoa(uint64(pol.Version)),
		"idcommit":  shortHex(idCommit[:]),
		"attrcount": uitoa(uint64(len(values))),
	}, "credential issued")

	return &credential.Bundle{
		Credential:    cred,
		ID:            id,
		IDCommitment:  idCommit,
		Salts:         salts,
		Attrs:         values,
		PolicyVersion: pol.Version,
		SpecNames:     names,
	}, nil
}

// Revoke 撤销指定凭证（立即对后续验证生效）。
func (i *Issuer) Revoke(credID []byte) error {
	err := i.reg.Revoke(credID)
	fields := map[string]string{"decision": "revoke", "basis": "operator_request"}
	if err != nil {
		fields["error"] = cerr.KindOf(err).String()
		i.emit("revoke", fields, "revocation rejected")
		return err
	}
	i.emit("revoke", fields, "credential revoked")
	return nil
}

// PublicKey 返回签发方公钥。
func (i *Issuer) PublicKey() []byte { return append([]byte(nil), i.key.Public...) }

// anonLabel 为签发日志生成不含 HolderID 明文的关联标签（仅取摘要前缀）。
func anonLabel(req *policy.IssuanceRequest) string {
	if req == nil || req.HolderID == "" {
		return "anon"
	}
	h := shortHex([]byte(req.HolderID))
	return h
}
