package anoncred

import (
	"crypto/rand"
	"encoding/binary"
	"io"
	"sync"
	"time"
)

// RNG 是可注入的随机源。生产使用 SecureRNG；测试可使用确定性 RNG。
type RNG interface {
	RandomBytes(n int) ([]byte, error)
}

// SecureRNG 基于 crypto/rand。
type SecureRNG struct{}

func (SecureRNG) RandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, err
	}
	return b, nil
}

// DeterministicRNG 是基于计数器的确定性伪随机源（非加密安全），
// 仅用于测试：以种子派生一个可重复的字节流。
type DeterministicRNG struct {
	mu  sync.Mutex
	seq uint64
}

// NewDeterministicRNG 使用给定种子创建确定性随机源。
func NewDeterministicRNG(seed uint64) *DeterministicRNG {
	return &DeterministicRNG{seq: seed}
}

func (d *DeterministicRNG) RandomBytes(n int) ([]byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]byte, 0, n)
	for len(out) < n {
		d.seq++
		var buf [8]byte
		binary.BigEndian.PutUint64(buf[:], d.seq*6364136223846793005+1442695040888963407)
		out = append(out, buf[:]...)
	}
	return out[:n], nil
}

// Clock 是可注入的时钟。生产使用 SystemClock；测试使用 FakeClock。
type Clock interface {
	Now() time.Time
}

// SystemClock 使用系统墙钟。
type SystemClock struct{}

func (SystemClock) Now() time.Time { return time.Now().UTC() }

// FakeClock 是可手动推进的线程安全测试时钟。
type FakeClock struct {
	mu  sync.Mutex
	now time.Time
}

// NewFakeClock 在给定时刻创建测试时钟。
func NewFakeClock(t time.Time) *FakeClock {
	return &FakeClock{now: t.UTC()}
}

func (c *FakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// Advance 将时钟向前推进 d。
func (c *FakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// Set 将时钟设置到指定时刻。
func (c *FakeClock) Set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = t.UTC()
}

// rngReader 将 RNG 适配为 io.Reader，供 crypto/ed25519 等库使用。
type rngReader struct{ rng RNG }

func (r rngReader) Read(p []byte) (int, error) {
	b, err := r.rng.RandomBytes(len(p))
	if err != nil {
		return 0, err
	}
	copy(p, b)
	return len(p), nil
}

// asReader 将随机源包装为 io.Reader。
func asReader(r RNG) io.Reader { return rngReader{rng: r} }
