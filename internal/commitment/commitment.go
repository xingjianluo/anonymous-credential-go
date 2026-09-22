// Package commitment 实现属性集合的固定槽位 Merkle 承诺与开放证明。
//
// 槽位顺序由策略属性名字典序固定，因此“同一属性”在所有版本的树中
// 位置可复算。叶子 = H_leaf(name || typed-value || salt)，盐由签发方
// 随机生成并交给持有者；未披露属性仅以兄弟摘要形式出现，不可反推
// 明文。Tree 是签发方/持有者进程内对象（内存中可持有盐与值），
// 对外出示的只有 Reveal 开放证明。
package commitment

import (
	"bytes"

	"github.com/xingjianluo/anonymous-credential-go/internal/canonical"
	cerr "github.com/xingjianluo/anonymous-credential-go/internal/errors"
	"github.com/xingjianluo/anonymous-credential-go/internal/policy"
)

// nullLeaf 是缺失（非必填）属性槽位的固定叶子，不含任何明文。
var nullLeaf = canonical.Hash("merkle-null-leaf-v1", canonical.EncodeString("__null__"))

// zeroHash 是 Merkle 配对时右侧补位的固定摘要。
var zeroHash [32]byte

// SaltedAttr 是单个属性的明文与其随机盐。
type SaltedAttr struct {
	Name string
	// Missing 为 true 表示可选属性未提供，槽位使用固定空叶子。
	Missing bool
	Value   any
	Salt    []byte
}

// Tree 是固定槽位的属性 Merkle 承诺树（进程内对象，不对外序列化）。
type Tree struct {
	specNames []string
	leaves    map[string][32]byte
	values    map[string]any
	salts     map[string][]byte
	missing   map[string]bool
}

// leafHash 计算单个带盐叶子。
func leafHash(name string, value any, salt []byte) ([32]byte, error) {
	spec, err := typedValueBytes(value)
	if err != nil {
		return [32]byte{}, cerr.Wrap(err, "leaf %q", name)
	}
	return canonical.Hash("merkle-leaf-v1",
		canonical.EncodeString(name), spec, canonical.EncodeBytes(salt)), nil
}

// typedValueBytes 按 Go 实际类型分派规范化编码（类型由策略保证）。
func typedValueBytes(v any) ([]byte, error) {
	switch x := v.(type) {
	case int64:
		return policy.EncodeValue(policy.AttrInt, x)
	case int:
		return policy.EncodeValue(policy.AttrInt, int64(x))
	case string:
		// AttrEnum 与 AttrString 的规范化编码一致。
		return policy.EncodeValue(policy.AttrString, x)
	default:
		return nil, cerr.New(cerr.KindMalformed, "unsupported value type %T in commitment", v)
	}
}

// Build 根据策略固定槽位名与属性集构造承诺树。
func Build(specNames []string, attrs []SaltedAttr) (*Tree, error) {
	byName := map[string]SaltedAttr{}
	for _, a := range attrs {
		if _, dup := byName[a.Name]; dup {
			return nil, cerr.New(cerr.KindMalformed, "duplicate attribute %q in commitment input", a.Name)
		}
		byName[a.Name] = a
	}
	t := &Tree{
		specNames: append([]string(nil), specNames...),
		leaves:    map[string][32]byte{},
		values:    map[string]any{},
		salts:     map[string][]byte{},
		missing:   map[string]bool{},
	}
	for _, name := range specNames {
		a, ok := byName[name]
		if !ok || a.Missing {
			t.leaves[name] = nullLeaf
			t.missing[name] = true
			continue
		}
		h, err := leafHash(name, a.Value, a.Salt)
		if err != nil {
			return nil, err
		}
		t.leaves[name] = h
		t.values[name] = a.Value
		t.salts[name] = append([]byte(nil), a.Salt...)
	}
	return t, nil
}

// hashLevel 对相邻节点两两配对求父节点，奇数右补 zeroHash。
func hashLevel(level [][32]byte) [][32]byte {
	next := make([][32]byte, 0, (len(level)+1)/2)
	for i := 0; i < len(level); i += 2 {
		l := level[i]
		r := zeroHash
		if i+1 < len(level) {
			r = level[i+1]
		}
		next = append(next, canonical.Hash("merkle-node-v1", l[:], r[:]))
	}
	return next
}

// Root 计算 Merkle 根。
func (t *Tree) Root() [32]byte {
	if len(t.specNames) == 0 {
		return canonical.Hash("merkle-empty-v1")
	}
	level := make([][32]byte, len(t.specNames))
	for i, n := range t.specNames {
		level[i] = t.leaves[n]
	}
	for len(level) > 1 {
		level = hashLevel(level)
	}
	return level[0]
}

// IsMissing 报告某槽位是否为空叶子。
func (t *Tree) IsMissing(name string) bool { return t.missing[name] }

// Reveal 是单个属性对外出示的开放证明。
type Reveal struct {
	Name string
	// Missing 为 true 时证明“该属性为空”，Value 必须为 nil。
	Missing bool
	Value   any
	Salt    []byte
	// Position 是该叶子在固定槽位序列中的下标。
	Position int
	// Siblings 自底向上每一层的兄弟摘要（补位层为 zeroHash）。
	Siblings [][32]byte
}

// Open 为指定属性生成从叶子到根的开放路径。
func (t *Tree) Open(name string) (*Reveal, error) {
	leaf, ok := t.leaves[name]
	if !ok {
		return nil, cerr.New(cerr.KindMalformed, "attribute %q is not part of commitment schema", name)
	}
	idx := -1
	for i, n := range t.specNames {
		if n == name {
			idx = i
			break
		}
	}
	r := &Reveal{Name: name, Position: idx}
	if t.missing[name] {
		r.Missing = true
	} else {
		r.Value = t.values[name]
		r.Salt = append([]byte(nil), t.salts[name]...)
	}
	level := make([][32]byte, len(t.specNames))
	for i, n := range t.specNames {
		level[i] = t.leaves[n]
	}
	cur := idx
	for len(level) > 1 {
		var sibling [32]byte
		if cur%2 == 0 {
			if cur+1 < len(level) {
				sibling = level[cur+1]
			} else {
				sibling = zeroHash
			}
		} else {
			sibling = level[cur-1]
		}
		r.Siblings = append(r.Siblings, sibling)
		level = hashLevel(level)
		cur /= 2
	}
	_ = leaf
	return r, nil
}

// treeDepth 返回 n 个槽位的 Merkle 路径深度（向上取整的 2 对数，至少 1）。
func treeDepth(n int) int {
	if n <= 1 {
		return 0
	}
	d := 0
	for n > 1 {
		n = (n + 1) / 2
		d++
	}
	return d
}

// Verify 用开放证明与公开根校验属性值确实在承诺中。
// totalSlots 是策略属性总数，用于严格校验路径深度，防止短路径伪造。
func Verify(root [32]byte, totalSlots int, r *Reveal) error {
	if r == nil {
		return cerr.New(cerr.KindMalformed, "nil reveal")
	}
	if totalSlots <= 0 {
		return cerr.New(cerr.KindMalformed, "non-positive total slots")
	}
	if r.Position < 0 || r.Position >= totalSlots {
		return cerr.New(cerr.KindProofInvalid, "reveal %q position %d out of range [0,%d)", r.Name, r.Position, totalSlots)
	}
	if len(r.Siblings) != treeDepth(totalSlots) {
		return cerr.New(cerr.KindProofInvalid, "reveal %q path depth %d != expected %d", r.Name, len(r.Siblings), treeDepth(totalSlots))
	}
	var h [32]byte
	if r.Missing {
		if r.Value != nil || len(r.Salt) != 0 {
			return cerr.New(cerr.KindProofInvalid, "missing reveal %q must carry no value or salt", r.Name)
		}
		h = nullLeaf
	} else {
		lh, err := leafHash(r.Name, r.Value, r.Salt)
		if err != nil {
			return err
		}
		h = lh
	}
	cur := r.Position
	for _, sib := range r.Siblings {
		if cur%2 == 0 {
			h = canonical.Hash("merkle-node-v1", h[:], sib[:])
		} else {
			h = canonical.Hash("merkle-node-v1", sib[:], h[:])
		}
		cur /= 2
	}
	if cur != 0 {
		return cerr.New(cerr.KindProofInvalid, "reveal %q path does not converge to a single root", r.Name)
	}
	if !bytes.Equal(h[:], root[:]) {
		return cerr.New(cerr.KindProofTampered, "merkle proof for %q does not match commitment root", r.Name)
	}
	return nil
}
