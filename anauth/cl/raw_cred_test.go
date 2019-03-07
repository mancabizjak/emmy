package cl

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRawCred_AddIntAttribute(t *testing.T) {
	c := NewRawCred()
	err := c.AddIntAttribute("Age", 122, true)
	assert.NoError(t, err)
	assert.Len(t, c.GetAttributes(), 1)
}

/*
func TestRawCred_AddStringAttribute(t *testing.T) {
	rc := NewRawCred()
	err := rc.AddStringAttribute("Name", "John")
	assert.NoError(t, err)
	a, _ := rc.GetAttribute("Name")
	assert.Equal(t, , a.internalValue())
}*/

// checks that when a duplicate parameter is created, error is
// reported.
func TestRawCred_AddDuplicate(t *testing.T) {
	c := NewRawCred()
	_ = c.AddIntAttribute("a", 10, true)
	err := c.AddIntAttribute("a", 12, false)
	assert.Error(t, err)
}

// FIXME we're missing a check for uniqueness of attributes
// TODO case insensitivity?

// check that we're able to fetch an attribute stored in raw credential.
func TestRawCred_GetAttribute(t *testing.T) {
	rc := NewRawCred()
	_ = rc.AddIntAttribute("test", 10, true)
	a, err := rc.GetAttribute("test")
	aCheck, _ := NewIntAttribute("test", 10, true)
	assert.NoError(t, err)
	assert.EqualValues(t, aCheck, a)
}

// check that an error is raised when we're trying to access an
// attribute that does not exist in the credential.
func TestRawCred_GetAttributeInvalid(t *testing.T) {
	rc := NewRawCred()
	a, err := rc.GetAttribute("test")
	assert.Error(t, err)
	assert.Nil(t, a)
}
