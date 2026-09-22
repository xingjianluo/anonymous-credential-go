package anoncred

import (
	"encoding/hex"
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
func (s *Service) RegisterPolicy(p Policy) error {
	pub, err := s.Issuer.AddPolicyVersion(p)
	if err != nil {
		return err
	}
	s.Trust.Register(TrustProfile{IssuerName: s.Issuer.name, Public: *pub})
	return nil
}

// IssueAndHold 执行“申请-签发-入钱包”的完整签发流程，返回凭证 ID（hex）。
func (s *Service) IssueAndHold(req IssueRequest) (string, error) {
	prep, err := s.Holder.PrepareIssue(req.Attributes, &IssueRequest{
		PolicyName:    req.PolicyName,
		PolicyVersion: req.PolicyVersion,
		TTL:           req.TTL,
		Attributes:    req.Attributes,
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
