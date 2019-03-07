package cl

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewIntAttribute(t *testing.T) {
	a, err := NewIntAttribute("a", 100, true)
	assert.NoError(t, err)
	assert.Equal(t, big.NewInt(100).Cmp(a.internalValue()), 0)
	assert.True(t, a.isKnown())
}

/*
func TestNewStringAttribute(t *testing.T) {
	a, err := NewStringAttribute("b", "c", false)
	//assert.Equal(t, big.NewInt(100).Cmp(a.internalValue()), 0)
	assert.NoError(t, err)
}*/
