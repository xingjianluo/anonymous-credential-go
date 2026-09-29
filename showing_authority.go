package anoncred

import (
	"bytes"
	"crypto/ed25519"
)

// AttestShowing 为一次 v2 不可关联出示签发会话绑定的短期背书。
//
// 核对在签发方内部完成，且具备下列隐私不变量：
//   - 仅凭一次性 RouteTag 定位凭证；RouteTag 每次出示不同，核对过程不向验证方
//     暴露 CredID，也不记录可跨出示串联的核对轨迹；
//   - 背书本身不含 CredID/化名/承诺集等任何长期标识；
//   - 撤销检查、有效性检查与纪元读取在同一临界区内原子完成：撤销一旦生效，
//     之后的新出示必失败。
func (is *Issuer) AttestShowing(env *ShowingEnvelope) (*ShowingAttestation, error) {
	if env == nil {
		return nil, Fail(CodeMalformedPresentation, "nil showing envelope")
	}
	if env.FormatVersion != ShowingFormatV2 {
		return nil, FailDetail(CodeIncompatibleParameters,
			"unsupported showing format version", itoa(env.FormatVersion))
	}
	if len(env.ShowID) == 0 || len(env.RouteTag) == 0 || len(env.SessionNonce) == 0 ||
		len(env.HolderShowKey) != ed25519.PublicKeySize || len(env.HolderAuth) == 0 {
		return nil, Fail(CodeMalformedPresentation, "showing envelope is missing required fields")
	}
	if env.PolicyName == "" {
		return nil, Fail(CodePolicyMismatch, "showing envelope carries no issuer name")
	}
	// 结构级去重：同一信封不得重复列出属性/谓词。
	discSet := map[string]bool{}
	for _, d := range env.Disclosed {
		if d.Name == "" || len(d.ValTag) == 0 {
			return nil, Fail(CodeMalformedPresentation, "shown attribute missing name or val tag")
		}
		if discSet[d.Name] {
			return nil, Fail(CodeMalformedPresentation, "duplicate shown attribute")
		}
		discSet[d.Name] = true
	}
	predSet := map[string]bool{}
	for _, p := range env.Predicates {
		if p == "" {
			return nil, Fail(CodeMalformedPresentation, "empty predicate name")
		}
		if predSet[p] {
			return nil, Fail(CodeMalformedPresentation, "duplicate predicate")
		}
		predSet[p] = true
	}

	// 全部核对（路由定位、撤销、有效期、持有者授权、披露与谓词）在同一把读锁下完成，
	// 使“撤销时刻 vs 核对时刻”可线性化。
	is.mu.RLock()
	defer is.mu.RUnlock()

	pub, ok := is.versions[env.PolicyVersion]
	if !ok || pub.Policy.Name != env.PolicyName {
		return nil, FailDetail(CodeUnknownVersion, "showing targets an unknown policy version",
			env.PolicyName+"#"+itoa(env.PolicyVersion))
	}
	priv, ok := is.signKeys[env.PolicyVersion]
	if !ok {
		return nil, FailDetail(CodeUnknownVersion, "issuer has no signing key for version",
			itoa(env.PolicyVersion))
	}

	var matched *IssuanceRecord
	for _, rec := range is.records {
		if rec.Legacy {
			continue // 旧格式凭证不能走 v2 背书路径
		}
		if rec.PolicyName != env.PolicyName || rec.PolicyVersion != env.PolicyVersion {
			continue
		}
		want := routeTag(rec.RoutingSecret, env.ShowID, env.SessionNonce,
			env.PolicyName, env.PolicyVersion)
		if bytes.Equal(want, env.RouteTag) {
			matched = rec
			break
		}
	}
	if matched == nil {
		// 不区分“凭证不存在”与“标签伪造”：对验证方都是无法背书，且不泄露存在性。
		return nil, Fail(CodeShowingRejected, "showing route tag matches no live credential")
	}
	if matched.Revoked {
		return nil, Fail(CodeRevokedCredential, "credential has been revoked")
	}
	now := is.clock.Now()
	if now.Before(matched.IssuedAt) || now.After(matched.ExpiresAt) {
		return nil, Fail(CodeExpiredCredential, "credential is not currently valid (time window)")
	}
	if now.Before(env.NotBefore) || now.After(env.ExpiresAt) {
		return nil, Fail(CodeExpiredCredential, "showing validity window does not cover current time")
	}

	// 持有者授权：凭证级一次性公钥必须认可本次的出示公钥与披露范围。
	if !ed25519.Verify(ed25519.PublicKey(matched.HolderVerifyKey),
		env.holderAuthPayload(), env.HolderAuth) {
		return nil, Fail(CodeBadHolderProof, "holder authorization for showing is invalid")
	}

	// 披露属性：重算一次性 ValTag（静态盐不出信封），并复查策略取值约定。
	for _, d := range env.Disclosed {
		salt, ok := matched.Salts[d.Name]
		if !ok {
			return nil, FailDetail(CodeTamperedDisclosure,
				"shown attribute is not present in credential", d.Name)
		}
		want := valTag(salt, env.ShowID, env.SessionNonce, d.Name, d.Value)
		if !bytes.Equal(want, d.ValTag) {
			return nil, FailDetail(CodeTamperedDisclosure,
				"shown value does not match the one-time value tag", d.Name)
		}
		if spec, ok := pub.Policy.attrSpec(d.Name); ok {
			if err := validateOne(spec, d.Value); err != nil {
				return nil, Fail(CodeInvalidAttributeValue, "shown value violates policy constraints")
			}
		} else {
			return nil, FailDetail(CodeDisclosureNotAllowed,
				"shown attribute is not defined by policy", d.Name)
		}
	}

	// 谓词：必须由同一签发方在签发时预签名、且与当前策略定义一致。
	signedCred := SignedCredential{
		CredID:     matched.CredID,
		PredTokens: matched.PredTokens,
	}
	for _, name := range env.Predicates {
		spec, ok := pub.Policy.predSpec(name)
		if !ok {
			return nil, FailDetail(CodePredicateNotAllowed, "predicate is not defined by trusted policy", name)
		}
		tok, ok := signedCred.PredTokens[name]
		if !ok {
			return nil, FailDetail(CodePredicateNotAllowed, "credential does not hold the predicate token", name)
		}
		if spec.Attr != tok.Attr || spec.Op != tok.Op ||
			spec.Threshold != tok.Threshold || spec.StrValue != tok.StrValue {
			return nil, FailDetail(CodeIncompatibleParameters,
				"predicate token parameters differ from policy", name)
		}
		pl := predPayload(matched.CredID, tok.Name, tok.Attr, tok.Op, tok.Threshold, tok.StrValue)
		if !ed25519.Verify(pub.VerifyingKey, pl, tok.Signature) {
			return nil, FailDetail(CodeBadIssuerSignature, "predicate token issuer signature verification failed", name)
		}
	}

	attrs := make([]string, 0, len(env.Disclosed))
	for _, d := range env.Disclosed {
		attrs = append(attrs, d.Name)
	}
	preds := append([]string(nil), env.Predicates...)
	att := &ShowingAttestation{
		FormatVersion:  ShowingFormatV2,
		ShowID:         append([]byte(nil), env.ShowID...),
		SessionNonce:   append([]byte(nil), env.SessionNonce...),
		HolderShowKey:  append([]byte(nil), env.HolderShowKey...),
		PolicyName:     env.PolicyName,
		PolicyVersion:  env.PolicyVersion,
		SchemaHash:     append([]byte(nil), pub.SchemaHash...),
		DisclosedAttrs: attrs,
		Predicates:     preds,
		NotBefore:      env.NotBefore,
		ExpiresAt:      env.ExpiresAt,
		RevEpoch:       is.revEpoch,
	}
	att.Signature = ed25519.Sign(priv, att.payload())
	return att, nil
}
