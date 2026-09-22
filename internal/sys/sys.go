// Package sys 提供可注入的时钟与随机源。
//
// 生产环境使用 RealClock + SystemRandom；测试使用 FixedClock +
// SeededRandom（确定性），从而无需等待、无需真正随机即可稳定复现。
package sys

import (
	"crypto/rand"
	mrand "math/rand/v2"
	"sync"
	"time"
)

// Clock 是可注入的时间源。
type Clock interface {
	Now() time.Time
}

// Random 是可注入的随机源，与 crypto/rand 的 Read 签名一致，
// 因而可直接传给 ed25519.GenerateKey。
type Random interface {
	Read(p []byte) (int, error)
}

// RealClock 使用系统墙钟（UTC）。
type RealClock struct{}

func (RealClock) Now() time.Time { return time.Now().UTC() }

// StepClock 是可被测试手动推进的并发安全时钟。
type StepClock struct {
	mu sync.RWMutex
	t  time.Time
}

// NewStepClock 从给定起点创建可推进时钟。
func NewStepClock(start time.Time) *StepClock { return &StepClock{t: start.UTC()} }

func (c *StepClock) Now() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.t
}

// Advance 将时钟向前推进 d。
func (c *StepClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// FixedClock 返回固定时间，供测试使用。
type FixedClock struct{ T time.Time }

func (c FixedClock) Now() time.Time { return c.T.UTC() }

// SystemRandom 包装 crypto/rand.Reader。
type SystemRandom struct{}

// NewSystemRandom 创建密码学安全随机源。
func NewSystemRandom() *SystemRandom { return &SystemRandom{} }

func (SystemRandom) Read(p []byte) (int, error) { return rand.Read(p) }

// SeededRandom 基于种子的确定性随机源（ChaCha8）。
// 输出仅用于可复现的测试，不得用于生产密钥。
type SeededRandom struct {
	r *mrand.Rand
}

// NewSeededRandom 用种子构造确定性随机源。
func NewSeededRandom(seed uint64) *SeededRandom {
	return &SeededRandom{r: mrand.New(mrand.NewChaCha8(encodeSeed(seed)))}
}

func encodeSeed(seed uint64) [32]byte {
	var b [32]byte
	for i := 0; i < 8; i++ {
		b[i] = byte(seed >> (8 * i))
	}
	// 域分隔标记，避免与其他用途的零填充种子状态完全相同。
	b[31] = 0xA5
	return b
}

// Read 用确定性流填充 p，永远返回完整长度。
func (r *SeededRandom) Read(p []byte) (int, error) {
	for i := 0; i < len(p); i += 8 {
		v := r.r.Uint64()
		for j := 0; j < 8 && i+j < len(p); j++ {
			p[i+j] = byte(v >> (8 * j))
		}
	}
	return len(p), nil
}
