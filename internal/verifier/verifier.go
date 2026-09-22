// Package verifier 实现验证方：会话管理、证明校验、撤销在线检查与
// 重放防护。
//
// Verify 的判定顺序（失败即返回对应可区分 Kind，并写日志）：
//  1. 会话存在、未过期，且证明的 SessionID/Challenge 与会话一致；
//  2. nullifier 未在本会话使用过（重复使用即 KindReplay）；
//  3. 策略版本已知、满足 MinAcceptedVersion，SchemaHash 一致；
//  4. 披露集合中的每个属性存在、Disclosable，Merkle 开放证明有效；
//     证明里不得夹带未声明披露的属性；
//  5. 谓词在披露值上全部成立；
//  6. 签发方签名覆盖整个凭证主体（含 CommitRoot/版本/模式/时间）；
//  7. 标识承诺与盲标签匹配、凭证未撤销（未知标识失败）；
//  8. 标记 nullifier 已用，防止同证明二次提交。
package verifier

import (
	"bytes"
	"sync"
	"time"

	"github.com/xingjianluo/anonymous-credential-go/internal/commitment"
	"github.com/xingjianluo/anonymous-credential-go/internal/credential"
	cerr "github.com/xingjianluo/anonymous-credential-go/internal/errors"
	"github.com/xingjianluo/anonymous-credential-go/internal/holder"
	"github.com/xingjianluo/anonymous-credential-go/internal/logging"
	"github.com/xingjianluo/anonymous-credential-go/internal/policy"
	"github.com/xingjianluo/anonymous-credential-go/internal/registry"
	"github.com/xingjianluo/anonymous-credential-go/internal/sys"
)

const challengeLen = 32

// Session 是一次证明会话。
type Session struct {
	ID        string
	Challenge []byte
	CreatedAt time.Time
	consumed  bool
}

// Result 是可解释的验证结论。
type Result struct {
	OK           bool
	SessionID    string
	DisclosedSet []string
	Basis        string
	Reason       string
	// RegistrySeq 是验证时观察到的签发登记操作序号，供并发测试
	// 在单一全序下核对“撤销/校验”结论。
	RegistrySeq uint64
}

// Verifier 是凭证验证方。
type Verifier struct {
	pub               []byte
	polreg            *policy.Registry
	reg               *registry.Registry
	clock             sys.Clock
	rng               sys.Random
	log               logging.Logger
	ttl               time.Duration
	minAcceptedPolicy uint32
	mu                sync.Mutex
	sessions          map[string]*Session
	used              map[string]map[[32]byte]bool // sessionID -> nullifiers
	sessionCtr        uint64
}

// New 构造验证方。minAcceptedPolicy 是接受凭证版本的下界。
func New(pub []byte, polreg *policy.Registry, reg *registry.Registry, clock sys.Clock, rng sys.Random, log logging.Logger, ttl time.Duration, minAcceptedPolicy uint32) *Verifier {
	return &Verifier{
		pub:               append([]byte(nil), pub...),
		polreg:            polreg,
		reg:               reg,
		clock:             clock,
		rng:               rng,
		log:               log,
		ttl:               ttl,
		minAcceptedPolicy: minAcceptedPolicy,
		sessions:          map[string]*Session{},
		used:              map[string]map[[32]byte]bool{},
	}
}

// NewSession 创建绑定随机挑战的会话。
func (v *Verifier) NewSession() (*Session, error) {
	ch := make([]byte, challengeLen)
	if _, err := v.rng.Read(ch); err != nil {
		return nil, cerr.Wrap(err, "generate session challenge")
	}
	v.mu.Lock()
	v.sessionCtr++
	id := sessionID(v.sessionCtr)
	s := &Session{ID: id, Challenge: ch, CreatedAt: v.clock.Now()}
	v.sessions[id] = s
	v.mu.Unlock()
	v.emit(id, map[string]string{"basis": "session_created"}, "verification session opened")
	return s, nil
}

func sessionID(n uint64) string {
	const digits = "0123456789abcdef"
	var b [16]byte
	for i := len(b) - 1; i >= 0; i-- {
		b[i] = digits[n&0xf]
		n >>= 4
	}
	return "sess-" + string(b[:])
}

func (v *Verifier) emit(sessionID string, fields map[string]string, msg string) {
	if v.log != nil {
		v.log.Log(sessionID, fields, msg)
	}
}

func disclosedFields(set []string, extra map[string]string) map[string]string {
	f := map[string]string{"disclosed": joinComma(set)}
	for k, val := range extra {
		f[k] = val
	}
	return f
}

// reject 统一写拒绝日志并返回 TypedError。
func (v *Verifier) reject(sid string, set []string, basis string, err error) error {
	v.emit(sid, disclosedFields(set, map[string]string{
		"decision": "reject",
		"basis":    basis,
		"error":    cerr.KindOf(err).String(),
	}), "presentation rejected: "+err.Error())
	return err
}

// Verify 在给定会话内校验证明。
func (v *Verifier) Verify(s *Session, p *holder.Presentation) (*Result, error) {
	set := disclosedSet(p)
	sid := sessionOf(s, p)

	if s == nil {
		return nil, v.reject(sid, set, "session_binding", cerr.New(cerr.KindMalformed, "nil session"))
	}
	if p == nil {
		return nil, v.reject(sid, set, "structure", cerr.New(cerr.KindMalformed, "nil presentation"))
	}

	// 1. 会话绑定与新鲜度（加锁原子完成状态检查）。
	v.mu.Lock()
	sess, exists := v.sessions[s.ID]
	if !exists {
		v.mu.Unlock()
		return nil, v.reject(sid, set, "session_binding", cerr.New(cerr.KindReplay, "session %q is unknown", s.ID))
	}
	if sess.consumed {
		v.mu.Unlock()
		return nil, v.reject(sid, set, "session_binding", cerr.New(cerr.KindReplay, "session %q has already been consumed", s.ID))
	}
	if v.ttl > 0 && v.clock.Now().Sub(sess.CreatedAt) > v.ttl {
		sess.consumed = true
		v.mu.Unlock()
		return nil, v.reject(sid, set, "session_binding", cerr.New(cerr.KindReplay, "session %q challenge expired", s.ID))
	}
	used := v.used[s.ID]
	if used != nil && used[p.Nullifier] {
		v.mu.Unlock()
		return nil, v.reject(sid, set, "nullifier_replay", cerr.New(cerr.KindReplay, "presentation nullifier already used in session %q", s.ID))
	}
	v.mu.Unlock()

	if p.SessionID != s.ID || !bytes.Equal(p.Challenge, s.Challenge) {
		return nil, v.reject(sid, set, "session_binding", cerr.New(cerr.KindReplay, "presentation is not bound to the current session"))
	}

	// 2. 版本与模式参数。
	pol, err := v.polreg.Get(p.PolicyVersion)
	if err != nil {
		return nil, v.reject(sid, set, "version", err)
	}
	if p.PolicyVersion < v.minAcceptedPolicy {
		return nil, v.reject(sid, set, "version", cerr.New(cerr.KindIncompatibleVersion,
			"credential policy v%d below verifier minimum v%d", p.PolicyVersion, v.minAcceptedPolicy))
	}
	schemaNow := pol.SchemaHash()
	if !bytes.Equal(p.SchemaHash[:], schemaNow[:]) {
		return nil, v.reject(sid, set, "version", cerr.New(cerr.KindIncompatibleVersion,
			"schema hash mismatch: credential parameters are incompatible with registered policy v%d", p.PolicyVersion))
	}

	// 3. 披露集合合法性（顺序、无夹带、全部可披露）。
	if p.TotalSlots != len(pol.Attrs) {
		return nil, v.reject(sid, set, "schema", cerr.New(cerr.KindIncompatibleVersion,
			"total slots %d != policy attr count %d", p.TotalSlots, len(pol.Attrs)))
	}
	order := append([]string(nil), p.DiscloseOrder...)
	if !sortedUnique(order) {
		return nil, v.reject(sid, set, "structure", cerr.New(cerr.KindMalformed, "disclosure set is not sorted/unique"))
	}
	if len(order) != len(p.Reveals) {
		return nil, v.reject(sid, set, "structure", cerr.New(cerr.KindUnauthorizedDisclosure,
			"reveal count %d does not match declared disclosure set size %d", len(p.Reveals), len(order)))
	}
	positions := map[int]string{}
	for _, name := range order {
		rv, ok := p.Reveals[name]
		if !ok {
			return nil, v.reject(sid, set, "structure", cerr.New(cerr.KindMalformed, "missing reveal body for %q", name))
		}
		spec, ok := pol.Attrs[name]
		if !ok {
			return nil, v.reject(sid, set, "disclosure_authorization",
				cerr.New(cerr.KindUnauthorizedDisclosure, "attribute %q not defined by policy", name))
		}
		if !spec.Disclosable {
			return nil, v.reject(sid, set, "disclosure_authorization",
				cerr.New(cerr.KindUnauthorizedDisclosure, "attribute %q must not be disclosed", name))
		}
		if prior, dup := positions[rv.Position]; dup {
			return nil, v.reject(sid, set, "structure", cerr.New(cerr.KindProofTampered,
				"two reveals occupy the same Merkle position: %q and %q", prior, name))
		}
		positions[rv.Position] = name
		// 4. Merkle 开放证明（叶子值与根绑定，任何字段篡改均失败）。
		rv2 := &commitment.Reveal{
			Name:     name,
			Value:    rv.Value,
			Salt:     rv.Salt,
			Position: rv.Position,
			Siblings: rv.Siblings,
		}
		if err := commitment.Verify(p.CommitRoot, p.TotalSlots, rv2); err != nil {
			return nil, v.reject(sid, set, "merkle_opening", err)
		}
		// 披露值仍须满足当前策略取值范围（范围收紧后旧值会在这里被解释性拒绝）。
		if err := checkAgainstSpec(spec, rv.Value); err != nil {
			return nil, v.reject(sid, set, "value_range", err)
		}
	}

	// 5. 谓词全部针对已披露属性且成立。
	for _, pred := range p.Predicates {
		if !contains(order, pred.Attr) {
			return nil, v.reject(sid, set, "predicate",
				cerr.New(cerr.KindUnauthorizedDisclosure, "predicate references undisclosed attribute %q", pred.Attr))
		}
		rv := p.Reveals[pred.Attr]
		if err := evalBound(rv.Value, pred); err != nil {
			return nil, v.reject(sid, set, "predicate", err)
		}
	}

	// 6. 重算凭证体并校验签发方签名（全部绑定字段均被覆盖）。
	body := &credential.Body{
		PolicyVersion: p.PolicyVersion,
		CommitRoot:    p.CommitRoot,
		SchemaHash:    p.SchemaHash,
		IssuedAt:      time.Unix(p.IssuedAtUnix, 0).UTC(),
	}
	cred := &credential.Credential{Body: *body, Signature: p.CredSignature}
	if err := credential.Verify(v.pub, cred); err != nil {
		return nil, v.reject(sid, set, "issuer_signature", err)
	}

	// 7. 在线撤销检查（未知标识与已撤销都失败）。
	status, err := v.reg.CheckBlinded(s.Challenge, p.BlindedRevID)
	if err != nil {
		return nil, v.reject(sid, set, "revocation_check", err)
	}
	observedSeq := status.ObservedSeq
	if !bytes.Equal(status.IDCommitment[:], p.IDCommitment[:]) {
		return nil, v.reject(sid, set, "revocation_check",
			cerr.New(cerr.KindProofTampered, "id commitment does not match issuance record"))
	}
	if status.Revoked {
		return nil, v.reject(sid, set, "revocation_status",
			cerr.New(cerr.KindCredentialRevoked, "credential has been revoked"))
	}

	// 8. 原子占用会话与 nullifier；与撤销/其他校验并发时结论线性一致。
	v.mu.Lock()
	if sess.consumed {
		v.mu.Unlock()
		return nil, v.reject(sid, set, "session_binding", cerr.New(cerr.KindReplay, "concurrent replay detected on session"))
	}
	if v.used[s.ID] == nil {
		v.used[s.ID] = map[[32]byte]bool{}
	}
	if v.used[s.ID][p.Nullifier] {
		v.mu.Unlock()
		return nil, v.reject(sid, set, "nullifier_replay", cerr.New(cerr.KindReplay, "concurrent nullifier replay detected"))
	}
	v.used[s.ID][p.Nullifier] = true
	sess.consumed = true
	v.mu.Unlock()

	v.emit(s.ID, disclosedFields(set, map[string]string{
		"decision": "accept",
		"basis":    "signature+opening+predicates+revocation+freshness",
		"policy_v": itoa(p.PolicyVersion),
	}), "presentation accepted")
	return &Result{
		OK:           true,
		SessionID:    s.ID,
		DisclosedSet: append([]string(nil), order...),
		Basis:        "issuer signature valid; merkle openings match; predicates satisfied; credential active; session fresh",
		Reason:       "accepted",
		RegistrySeq:  observedSeq,
	}, nil
}

func disclosedSet(p *holder.Presentation) []string {
	if p == nil {
		return nil
	}
	return append([]string(nil), p.DiscloseOrder...)
}

func sessionOf(s *Session, p *holder.Presentation) string {
	if s != nil && s.ID != "" {
		return s.ID
	}
	if p != nil && p.SessionID != "" {
		return p.SessionID
	}
	return "-"
}

func checkAgainstSpec(spec *policy.AttrSpec, v any) error {
	// 复用策略包的类型编码能力，范围规则与签发时完全一致。
	switch spec.Type {
	case policy.AttrInt:
		n, ok := toI64(v)
		if !ok {
			return cerr.New(cerr.KindProofTampered, "disclosed %q has wrong type", spec.Name)
		}
		if n < spec.Min || n > spec.Max {
			return cerr.New(cerr.KindIncompatibleVersion, "disclosed %q=%d no longer within policy range [%d,%d]", spec.Name, n, spec.Min, spec.Max)
		}
	case policy.AttrEnum:
		s, ok := v.(string)
		if !ok || !containsStr(spec.EnumValues, s) {
			return cerr.New(cerr.KindIncompatibleVersion, "disclosed %q no longer in policy enum set", spec.Name)
		}
	case policy.AttrString:
		if _, ok := v.(string); !ok {
			return cerr.New(cerr.KindProofTampered, "disclosed %q has wrong type", spec.Name)
		}
	}
	return nil
}

func evalBound(got any, pred holder.Predicate) error {
	switch pred.Op {
	case "eq":
		gn, ok1 := toI64(got)
		wn, ok2 := toI64(pred.Value)
		if ok1 && ok2 {
			if gn != wn {
				return cerr.New(cerr.KindProofInvalid, "predicate eq(%q): %d != %d", pred.Attr, gn, wn)
			}
			return nil
		}
		if fmtSprint(got) != fmtSprint(pred.Value) {
			return cerr.New(cerr.KindProofInvalid, "predicate eq(%q) failed", pred.Attr)
		}
		return nil
	case "gte":
		gn, ok1 := toI64(got)
		wn, ok2 := toI64(pred.Value)
		if !ok1 || !ok2 {
			return cerr.New(cerr.KindMalformed, "predicate gte(%q) needs integers", pred.Attr)
		}
		if gn < wn {
			return cerr.New(cerr.KindProofInvalid, "predicate gte(%q): %d < %d", pred.Attr, gn, wn)
		}
		return nil
	default:
		return cerr.New(cerr.KindMalformed, "unsupported predicate op %q", pred.Op)
	}
}

func fmtSprint(v any) string {
	switch x := v.(type) {
	case string:
		return x
	default:
		if n, ok := toI64(v); ok {
			return itoa(uint32(n))
		}
		return ""
	}
}

func toI64(v any) (int64, bool) {
	switch n := v.(type) {
	case int:
		return int64(n), true
	case int64:
		return n, true
	default:
		return 0, false
	}
}

func sortedUnique(xs []string) bool {
	for i := 1; i < len(xs); i++ {
		if xs[i-1] >= xs[i] {
			return false
		}
	}
	return true
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func containsStr(xs []string, x string) bool { return contains(xs, x) }

func joinComma(xs []string) string {
	if len(xs) == 0 {
		return "-"
	}
	out := ""
	for i, x := range xs {
		if i > 0 {
			out += ","
		}
		out += x
	}
	return out
}

func itoa(v uint32) string {
	if v == 0 {
		return "0"
	}
	var b [16]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}
