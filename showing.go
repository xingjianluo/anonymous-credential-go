package anoncred

import (
	"crypto/sha256"
	"sort"
	"time"
)

// ShowingFormatV2 是“多次出示不可关联”的证明格式版本。
const ShowingFormatV2 = 2

// ShownAttribute 是 v2 出示中被披露的单个属性。
//
// 与旧格式不同：属性盐绝不出现在证明字节中；持有者改用以每次出示随机数
// 派生的一次性 ValTag，供签发方在不出示长期标识的情况下核对。
type ShownAttribute struct {
	Name   string `json:"name"`
	Value  Value  `json:"value"`
	ValTag []byte `json:"val_tag"`
}

// ShowingEnvelope 是 v2 出示请求的公开信封（持有者 -> 验证方 -> 签发方）。
//
// 不变量（见 unlinkable_test.go）：
//   - 不含 CredID、化名、凭证级持有公钥、属性承诺集合、静态盐等任何长期标识；
//   - ShowID / RouteTag / HolderShowKey 每次出示全新随机，不可跨出示复用；
//   - RouteTag 只能让签发方在“本次”核对中定位凭证，验证方无法据其串联多次出示。
type ShowingEnvelope struct {
	FormatVersion int `json:"format_version"`

	PolicyName    string `json:"policy_name"`
	PolicyVersion int    `json:"policy_version"`

	ShowID   []byte `json:"show_id"`
	RouteTag []byte `json:"route_tag"`

	// HolderShowKey 为本次出示一次性的持有者公钥；由凭证级持有密钥授权（HolderAuth）。
	HolderShowKey []byte `json:"holder_show_key"`
	// HolderAuth 由凭证级持有私钥签名，签发方核对后才会背书（不出现在背书之后的长期轨迹中）。
	HolderAuth []byte `json:"holder_auth"`

	SessionNonce []byte `json:"session_nonce"`

	Disclosed  []ShownAttribute `json:"disclosed"`
	Predicates []string         `json:"predicates"`

	NotBefore   time.Time `json:"not_before"`
	ExpiresAt   time.Time `json:"expires_at"`
	GeneratedAt time.Time `json:"generated_at"`

	// HolderProof 由一次性 HolderShowKey 对应私钥对信封签名（背书不可搬移到其他信封）。
	HolderProof []byte `json:"holder_proof"`
}

// ShowingAttestation 是签发方对一次 v2 出示的短期、会话绑定背书。
//
// 背书中不含任何凭证/持有者长期标识；验证方凭受信签发方公钥即可确认：
// 某个状态正常（未撤销、在有效期、模式匹配、披露与谓词属实）的持有者
// 在本会话中授权了这些披露项。
type ShowingAttestation struct {
	FormatVersion  int       `json:"format_version"`
	ShowID         []byte    `json:"show_id"`
	SessionNonce   []byte    `json:"session_nonce"`
	HolderShowKey  []byte    `json:"holder_show_key"`
	PolicyName     string    `json:"policy_name"`
	PolicyVersion  int       `json:"policy_version"`
	SchemaHash     []byte    `json:"schema_hash"`
	DisclosedAttrs []string  `json:"disclosed_attrs"`
	Predicates     []string  `json:"predicates"`
	NotBefore      time.Time `json:"not_before"`
	ExpiresAt      time.Time `json:"expires_at"`
	// RevEpoch 为背书时刻签发方的撤销纪元；验证方在窗口末端复核纪元以保证线性化。
	RevEpoch  uint64 `json:"rev_epoch"`
	Signature []byte `json:"signature"`
}

// ShowingAuthority 是验证方用来为单次 v2 出示获取签发方背书的抽象。
// Issuer 直接实现；核对过程不得暴露或记录可跨出示串联的长期标识。
type ShowingAuthority interface {
	AttestShowing(env *ShowingEnvelope) (*ShowingAttestation, error)
}

// --- 规范编码 ----------------------------------------------------------------

func hashPrefixed(domain string, parts ...[]byte) []byte {
	var b []byte
	b = append(b, []byte(domain)...)
	for _, p := range parts {
		b = writeLengthPrefixed(b, p)
	}
	sum := sha256.Sum256(b)
	return sum[:]
}

// routeTag 派生本次出示的一次性路由标签：
//
//	SHA-256("anoncred:route:v2" | routingSecret | showID | sessionNonce | issuer#version)
//
// routingSecret 是仅签发方/持有者知道的每凭证随机秘密；不同 showID/sessionNonce
// 产生不同标签，验证方既不知道秘密也无法枚举，因而无法把多次出示串联。
func routeTag(routingSecret, showID, sessionNonce []byte, issuer string, version int) []byte {
	return hashPrefixed("anoncred:route:v2",
		routingSecret, showID, sessionNonce, []byte(issuer+"#"+itoa(version)))
}

// valTag 派生被披露属性的一次性核对标签：
//
//	SHA-256("anoncred:valtag:v2" | salt | showID | sessionNonce | attrName | encode(value))
//
// 静态盐本身不上链/不出示；签发方留存盐后可在本次核对中重算该一次性标签。
func valTag(salt, showID, sessionNonce []byte, attrName string, v Value) []byte {
	return hashPrefixed("anoncred:valtag:v2",
		salt, showID, sessionNonce, []byte(attrName), encodeValue(v))
}

// holderAuthPayload 返回凭证级持有密钥对本次出示授权的签名摘要。
//
// 摘要覆盖：一次性出示公钥、会话随机数、出示 ID、策略定位、有效期，
// 以及每个披露项（名称+一次性值标签）与谓词名集合。背书签发方据此确信
// “凭证持有者授权了本次一次性出示公钥与披露范围”。
func (e *ShowingEnvelope) holderAuthPayload() []byte {
	var b []byte
	b = append(b, []byte("anoncred:showauth:v2")...)
	b = writeLengthPrefixed(b, e.HolderShowKey)
	b = writeLengthPrefixed(b, e.SessionNonce)
	b = writeLengthPrefixed(b, e.ShowID)
	b = writeLengthPrefixed(b, []byte(e.PolicyName))
	b = appendInt64(b, int64(e.PolicyVersion))
	b = appendTime(b, e.NotBefore)
	b = appendTime(b, e.ExpiresAt)

	disc := make([]ShownAttribute, len(e.Disclosed))
	copy(disc, e.Disclosed)
	sortShownAttrs(disc)
	for _, d := range disc {
		b = writeLengthPrefixed(b, []byte(d.Name))
		b = writeLengthPrefixed(b, d.ValTag)
	}

	preds := append([]string(nil), e.Predicates...)
	sort.Strings(preds)
	for _, p := range preds {
		b = writeLengthPrefixed(b, []byte(p))
	}
	return b
}

// attestPayload 返回签发方背书的签名摘要。
func (a *ShowingAttestation) payload() []byte {
	var b []byte
	b = append(b, []byte("anoncred:attest:v2")...)
	b = appendInt64(b, int64(a.FormatVersion))
	b = writeLengthPrefixed(b, a.ShowID)
	b = writeLengthPrefixed(b, a.SessionNonce)
	b = writeLengthPrefixed(b, a.HolderShowKey)
	b = writeLengthPrefixed(b, []byte(a.PolicyName))
	b = appendInt64(b, int64(a.PolicyVersion))
	b = writeLengthPrefixed(b, a.SchemaHash)
	b = appendTime(b, a.NotBefore)
	b = appendTime(b, a.ExpiresAt)
	b = appendInt64(b, int64(a.RevEpoch))

	attrs := append([]string(nil), a.DisclosedAttrs...)
	sort.Strings(attrs)
	for _, n := range attrs {
		b = writeLengthPrefixed(b, []byte(n))
	}
	preds := append([]string(nil), a.Predicates...)
	sort.Strings(preds)
	for _, p := range preds {
		b = writeLengthPrefixed(b, []byte(p))
	}
	return b
}

// showProofPayload 返回一次性出示密钥对信封的签名摘要。
//
// 一次性出示私钥只存在于持有者钱包：复制了信封（及后续背书）的攻击者无法生成
// 该签名，因而背书无法被搬到另一个信封/会话上接受。背书与信封的绑定则由
// 验证方逐字段比对 ShowID/SessionNonce/HolderShowKey 及签发方背书签名保证。
func showProofPayload(e *ShowingEnvelope) []byte {
	var b []byte
	b = append(b, []byte("anoncred:showproof:v2")...)
	b = writeLengthPrefixed(b, e.RouteTag)
	b = writeLengthPrefixed(b, e.SessionNonce)
	b = writeLengthPrefixed(b, e.ShowID)
	b = writeLengthPrefixed(b, e.HolderShowKey)

	disc := make([]ShownAttribute, len(e.Disclosed))
	copy(disc, e.Disclosed)
	sortShownAttrs(disc)
	for _, d := range disc {
		b = writeLengthPrefixed(b, []byte(d.Name))
		b = writeLengthPrefixed(b, encodeValue(d.Value))
		b = writeLengthPrefixed(b, d.ValTag)
	}
	preds := append([]string(nil), e.Predicates...)
	sort.Strings(preds)
	for _, p := range preds {
		b = writeLengthPrefixed(b, []byte(p))
	}
	return b
}

func sortShownAttrs(s []ShownAttribute) {
	sort.Slice(s, func(i, j int) bool { return s[i].Name < s[j].Name })
}
