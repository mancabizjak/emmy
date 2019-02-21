package cl

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRawCred_GetAttribute(t *testing.T) {
	rc := NewRawCred()
	_ = rc.AddIntAttribute("A", 100)
	_ = rc.AddStringAttribute("D", "test")

	attr1, err := rc.GetAttribute("A")
	assert.NoError(t, err)
	assert.EqualValues(t, , attr1)

	attr2, err := rc.GetAttribute("D")
	assert.NoError(t, err)
	assert.EqualValues(t, , attr2)
}

func TestRawCred_AddIntAttribute(t *testing.T) {
	rc := NewRawCred()
	err := rc.AddIntAttribute("Age", 122)
	assert.NoError(t, err)

	/*values := rc.GetAttributeValues()
	attrValues := map[int]string{0: "John", 1: "M", 2: "122"}

	assert.Equal(t, attrValues, values,
	"raw credential attributes setting does not work")*/
}

func TestRawCred_AddStringAttribute(t *testing.T) {
	rc := NewRawCred()
	err := rc.AddStringAttribute("Name", "John")
	assert.NoError(t, err)
	a, _ := rc.GetAttribute("Name")
	assert.Equal(t, , a.internalValue())
}
