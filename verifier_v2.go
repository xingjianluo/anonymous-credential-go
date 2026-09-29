package anoncred

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"sort"
	"time"
)

// verifyV2 校验一次 v2 不可关联出示：
//
//	结构校验 -> 会话/版本/信任 -> 请求签发方背书（内含原子撤销核对）->
//	背书签名/字段一致性 -> 一次性持有者证明 -> 撤销纪元线性化。
//
// 整条链路中验证方拿不到 CredID/化名/承诺集，无法把本次出示与任何其他出示串联。
func (v *Verifier) verifyV2(sess *Session, pres *Presentation, now time.Time) (*Decision, error) {
	env := pres.Showing

	d := &Decision{
		SessionID:      sess.ID,
		Issuer:         sess.Issuer,
		PolicyVersion:  sess.Version,
		CredID:         "", // v2：决策记录刻意不携带任何长期标识
		ShowID:         hex.EncodeToString(env.ShowID),
		DisclosedAttrs: shownAttrNames(env.Disclosed),
		Predicates:     append([]string(nil), env.Predicates...),
		CheckedAt:      now,
	}
	sort.Strings(d.Predicates)
	fail := func(c Code, msg, detail string) (*Decision, error) {
		d.Reason = c
		v.logDecision(d, msg)
		return d, FailDetail(c, msg, detail)
	}

	// 1) 信封结构完整性。
	if env.FormatVersion != ShowingFormatV2 {
		return fail(CodeIncompatibleParameters, "unsupported showing format version",
			itoa(env.FormatVersion))
	}
	if len(env.ShowID) == 0 || len(env.RouteTag) == 0 ||
		len(env.HolderShowKey) != ed25519.PublicKeySize ||
		len(env.HolderAuth) == 0 || len(env.HolderProof) == 0 {
		return fail(CodeMalformedPresentation, "showing envelope is missing required fields", "")
	}
	if !bytes.Equal(env.SessionNonce, sess.Nonce) {
		return fail(CodeProofReplay, "showing nonce does not match the single-use session nonce", "")
	}

	// 2) 签发方/版本/信任。
	if env.PolicyName != sess.Issuer {
		return fail(CodePolicyMismatch, "showing issuer differs from session issuer",
			"got="+env.PolicyName+" want="+sess.Issuer)
	}
	if env.PolicyVersion != sess.Version {
		return fail(CodeIncompatibleParameters,
			"showing version does not match the session version",
			"show="+itoa(env.PolicyVersion)+" session="+itoa(sess.Version))
	}
	tp := v.trust.Lookup(sess.Issuer, sess.Version)
	if tp == nil {
		return fail(CodeUnknownVersion, "showing version is not registered in trust store",
			trustKey(sess.Issuer, sess.Version))
	}
	if tp.Rejected {
		return fail(CodeVersionRejected, "showing version has been explicitly rejected",
			trustKey(sess.Issuer, sess.Version))
	}

	// 3) 披露范围必须在会话白名单内（越权披露）。
	allowAttr := map[string]bool{}
	for _, a := range sess.Policy.AllowAttrs {
		allowAttr[a] = true
	}
	allowPred := map[string]bool{}
	for _, p := range sess.Policy.AllowPredicates {
		allowPred[p] = true
	}
	discSeen := map[string]bool{}
	for _, da := range env.Disclosed {
		if da.Name == "" || len(da.ValTag) == 0 {
			return fail(CodeMalformedPresentation, "shown attribute missing name or val tag", da.Name)
		}
		if !allowAttr[da.Name] {
			return fail(CodeDisclosureNotAllowed, "shown attribute is not allowed by session", da.Name)
		}
		if discSeen[da.Name] {
			return fail(CodeMalformedPresentation, "duplicate shown attribute", da.Name)
		}
		discSeen[da.Name] = true
	}
	predSeen := map[string]bool{}
	for _, p := range env.Predicates {
		if !allowPred[p] {
			return fail(CodePredicateNotAllowed, "presented predicate is not allowed by session", p)
		}
		if predSeen[p] {
			return fail(CodeMalformedPresentation, "duplicate predicate", p)
		}
		predSeen[p] = true
	}

	// 4) 信封展示时效（凭证有效期由签发方在背书时核对）。
	if now.Before(env.NotBefore) || now.After(env.ExpiresAt) {
		return fail(CodeExpiredCredential, "showing is not currently valid (time window)", "")
	}

	// 5) 持有者一次性证明必须由信封中的一次性公钥校验通过：
	//    保证背书不会被搬到攻击者自制的另一个信封上。
	if !ed25519.Verify(ed25519.PublicKey(env.HolderShowKey),
		showProofPayload(env), env.HolderProof) {
		return fail(CodeBadHolderProof, "one-time showing holder proof verification failed", "")
	}

	// 6) 校验窗口起点的撤销纪元（与旧路径同一线性化语义）。
	var epochBefore uint64
	if v.revoke != nil {
		epochBefore = v.revoke.RevocationEpoch()
	}

	// 7) 请求签发方背书：撤销/有效性/持有者授权/披露与谓词核对均在其内部原子完成。
	if v.showing == nil {
		return fail(CodeShowingRejected, "verifier has no showing authority configured", "")
	}
	att, err := v.showing.AttestShowing(env)
	if err != nil {
		return fail(CodeOf(err), "issuer refused to attest the showing", "")
	}

	// 8) 背书必须由受信签发方当前版本密钥签名。
	if !bytes.Equal(att.SchemaHash, tp.Public.SchemaHash) {
		return fail(CodeIncompatibleParameters,
			"attestation schema hash does not match trusted parameters", "")
	}
	if !ed25519.Verify(tp.Public.VerifyingKey, att.payload(), att.Signature) {
		return fail(CodeBadIssuerSignature, "showing attestation issuer signature verification failed", "")
	}

	// 9) 背书与信封逐字段绑定：防止“为 A 会话取得的背书用于 B 信封”。
	if !bytes.Equal(att.ShowID, env.ShowID) ||
		!bytes.Equal(att.SessionNonce, env.SessionNonce) ||
		!bytes.Equal(att.HolderShowKey, env.HolderShowKey) ||
		att.PolicyName != env.PolicyName || att.PolicyVersion != env.PolicyVersion ||
		!equalStringSets(att.DisclosedAttrs, d.DisclosedAttrs) ||
		!equalStringSets(att.Predicates, d.Predicates) {
		return fail(CodeIncompatibleParameters,
			"attestation does not bind to this showing envelope", "")
	}
	if now.Before(att.NotBefore) || now.After(att.ExpiresAt) {
		return fail(CodeExpiredCredential, "attestation window does not cover current time", "")
	}

	// 10) 窗口末端撤销纪元：与背书时刻纪元比较，推进则说明与某次撤销并发交错，保守拒绝。
	if v.revoke != nil {
		epochAfter := v.revoke.RevocationEpoch()
		if epochAfter != att.RevEpoch || epochBefore != att.RevEpoch {
			return fail(CodeRevokedCredential,
				"revocation registry changed around verification; refusing stale acceptance", "")
		}
	}

	d.Accepted = true
	v.logDecision(d, "accepted")
	return d, nil
}

func shownAttrNames(s []ShownAttribute) []string {
	out := make([]string, 0, len(s))
	for _, a := range s {
		out = append(out, a.Name)
	}
	sort.Strings(out)
	return out
}

func equalStringSets(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	x := append([]string(nil), a...)
	y := append([]string(nil), b...)
	sort.Strings(x)
	sort.Strings(y)
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}
