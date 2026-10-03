package anoncred

import (
	"encoding/hex"
	"sync"
	"time"
)

// Service 把签发方、持有者、验证方与审计日志装配为一个本地可运行的模拟系统。
type Service struct {
	Issuer   *Issuer
	Holder   *Holder
	Verifier *Verifier
	Trust    *TrustRegistry
	Audit    *AuditLogger
	Clock    Clock

	// registerMu 串行化跨组件（签发方 + 信任库）的策略登记全过程。
	// 多个初始化执行流并发登记同一版本时，登记步骤之间不会交错“签发/验证”：
	// 每次成功的 RegisterPolicy 对外部都等价于一次不可分割的串行登记。
	registerMu sync.Mutex
}

// ServiceConfig 为装配参数；nil 字段使用安全默认值。
//
// 签发方对外名称由首个登记的策略名决定（与凭证 PolicyName 一致）。
type ServiceConfig struct {
	IssuerRNG   RNG
	HolderRNG   RNG
	VerifierRNG RNG
	Clock       Clock
}

// NewService 创建本地模拟服务（不预置策略）。
func NewService(cfg ServiceConfig) *Service {
	if cfg.Clock == nil {
		cfg.Clock = SystemClock{}
	}
	if cfg.IssuerRNG == nil {
		cfg.IssuerRNG = SecureRNG{}
	}
	if cfg.HolderRNG == nil {
		cfg.HolderRNG = SecureRNG{}
	}
	if cfg.VerifierRNG == nil {
		cfg.VerifierRNG = SecureRNG{}
	}
	audit := NewAuditLogger(nil)
	// 签发方对外名称由首个登记的策略名决定（与凭证 PolicyName 一致）。
	iss := NewIssuer("", cfg.IssuerRNG, cfg.Clock).WithAudit(audit)
	hold := NewHolder("local-holder", cfg.HolderRNG).WithClock(cfg.Clock)
	trust := NewTrustRegistry()
	ver := NewVerifier(cfg.Clock, cfg.VerifierRNG, trust).
		WithRevocationSource(iss).
		WithShowingAuthority(iss).
		WithAudit(audit)
	return &Service{
		Issuer:   iss,
		Holder:   hold,
		Verifier: ver,
		Trust:    trust,
		Audit:    audit,
		Clock:    cfg.Clock,
	}
}

// RegisterPolicy 向签发方与验证方信任库同时登记策略版本。
//
// 同一版本号重复登记：参数一致幂等；任一侧参数不一致返回 version_conflict，
// 绝不会被悄悄覆盖。
//
// 并发语义：整个登记过程由服务级互斥锁串行化，且签发方内部的
// “检查—生成密钥—写入”本身也是原子的。因此无论多少执行流并发登记同一版本，
// 可观察结果都与按某种顺序串行登记完全一致：
//   - 参数完全一致：全部成功，且共享首次发布的同一份签名密钥与公开材料；
//   - 参数不一致：恰好首次发布的那一种参数生效，其余每次登记都得到可区分的
//     version_conflict，失败方不改动签发方或信任库的任何已发布状态；
//   - 不会出现“签发方与信任库各持一份不同密钥”的半更新状态：若某版本是本次
//     首发、而信任库登记失败，则回滚签发方这次首发，系统回到登记前状态。
func (s *Service) RegisterPolicy(p Policy) error {
	s.registerMu.Lock()
	defer s.registerMu.Unlock()

	before := s.Issuer.hasVersion(p.Version)
	pub, err := s.Issuer.AddPolicyVersion(p)
	if err != nil {
		return err
	}
	if err := s.Trust.Register(TrustProfile{IssuerName: s.Issuer.name, Public: *pub}); err != nil {
		// 仅当该版本确为本次首发时才回滚；重复发布场景下既有版本必须保留。
		if !before {
			s.Issuer.removeFreshVersion(p.Version)
		}
		return err
	}
	return nil
}

// RegisterLegacyPolicy 登记策略版本并声明旧格式凭证的兼容窗口；
// end 为零值表示窗口无限（迁移/测试用途）。
func (s *Service) RegisterLegacyPolicy(p Policy, end time.Time) error {
	if err := s.RegisterPolicy(p); err != nil {
		return err
	}
	return s.Trust.SetLegacyWindow(s.Issuer.name, p.Version, end)
}

// SetLegacyWindow 为已登记版本更新旧格式兼容窗口。
func (s *Service) SetLegacyWindow(version int, end time.Time) error {
	return s.Trust.SetLegacyWindow(s.Issuer.name, version, end)
}

// IssueAndHold 执行“申请-签发-入钱包”的完整签发流程，返回凭证 ID（hex）。
func (s *Service) IssueAndHold(req IssueRequest) (string, error) {
	prep, err := s.Holder.PrepareIssue(req.Attributes, &IssueRequest{
		PolicyName:    req.PolicyName,
		PolicyVersion: req.PolicyVersion,
		TTL:           req.TTL,
		Attributes:    req.Attributes,
		Legacy:        req.Legacy,
	})
	if err != nil {
		return "", err
	}
	cred, err := s.Issuer.Issue(*prep)
	if err != nil {
		return "", err
	}
	pub := s.Issuer.ActivePublic()
	if err := s.Holder.Accept(cred, pub, prep.HolderSignKey); err != nil {
		return "", err
	}
	return hex.EncodeToString(cred.Signed.CredID), nil
}

// ProveResult 是一次出示的会话与证明。
type ProveResult struct {
	SessionID    string
	Presentation *Presentation
}

// Prove 为持有者的一次选择性披露创建会话并生成证明。
func (s *Service) Prove(credIDHex string, pol VerifyPolicy, discloseAttrs, disclosePreds []string) (*ProveResult, error) {
	cred := s.Holder.lookup(credIDHex)
	if cred == nil {
		return nil, FailDetail(CodeNoSuchCredential, "holder has no such credential", credIDHex)
	}
	sess, err := s.Verifier.NewSession(s.Issuer.name, cred.Cred.Signed.PolicyVersion, pol)
	if err != nil {
		return nil, err
	}
	pres, err := s.Holder.BuildPresentation(PresentRequest{
		CredIDHex:     credIDHex,
		SessionNonce:  sess.Nonce,
		DiscloseAttrs: discloseAttrs,
		DisclosePreds: disclosePreds,
	})
	if err != nil {
		return nil, err
	}
	return &ProveResult{SessionID: sess.ID, Presentation: pres}, nil
}

// Check 执行验证方校验（结论同时写入审计日志）。
func (s *Service) Check(sessionID string, pres *Presentation) (*Decision, error) {
	return s.Verifier.Verify(sessionID, pres)
}

// Revoke 由签发方吊销凭证。
func (s *Service) Revoke(credIDHex, reason string) error {
	id, err := hex.DecodeString(credIDHex)
	if err != nil {
		return Fail(CodeMalformedPresentation, "credential id is not hex encoded")
	}
	return s.Issuer.Revoke(id, reason)
}

// defaultTTL 为默认有效期。
const defaultTTL = 24 * time.Hour
