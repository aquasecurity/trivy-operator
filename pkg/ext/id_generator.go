package ext

import (
	"fmt"
	"sync/atomic"

	"github.com/google/uuid"
)

// IDGenerator defines contract for generating universally unique identifiers.
type IDGenerator interface {
	// GenerateID generates a new identifier.
	GenerateID() string
}

// NewGoogleUUIDGenerator constructs a new IDGenerator implemented with Google's UUID module.
func NewGoogleUUIDGenerator() IDGenerator {
	return &googleUUIDGenerator{}
}

type googleUUIDGenerator struct{}

func (g *googleUUIDGenerator) GenerateID() string {
	return uuid.New().String()
}

// NewSimpleIDGenerator constructs a simple IDGenerator that starts at 1, increments up to
// 999999999999, and then rolls over.
func NewSimpleIDGenerator() IDGenerator {
	return &simpleIDGenerator{}
}

type simpleIDGenerator struct {
	leastSigBits uint64
}

func (g *simpleIDGenerator) GenerateID() string {
	return fmt.Sprintf("00000000-0000-0000-0000-%012d", atomic.AddUint64(&g.leastSigBits, 1))
}
