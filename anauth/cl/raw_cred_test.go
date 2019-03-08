package cl

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRawCred_EmptyAttributeName(t *testing.T) {
	nAttrs := NewAttrCount(1, 1, 1)
	rc := NewRawCred(nAttrs)
	err := rc.AddInt64Attr("", 0, true)
	assert.Error(t, err)
}

func TestRawCred_ExceedKnownAttrsCount(t *testing.T) {
	nAttrs := NewAttrCount(0, 0, 0)
	rc := NewRawCred(nAttrs)
	err := rc.AddInt64Attr("a", 0, true)
	assert.Error(t, err)
}

func TestRawCred_ExceedCommittedAttrsCount(t *testing.T) {
	nAttrs := NewAttrCount(0, 0, 0)
	rc := NewRawCred(nAttrs)
	err := rc.AddInt64Attr("a", 0, false)
	assert.Error(t, err)
}

func TestRawCred_AddInt64Attr(t *testing.T) {
	c := NewRawCred(NewAttrCount(1, 0, 0))
	err := c.AddInt64Attr("Age", 122, true)
	assert.NoError(t, err)
	assert.Len(t, c.GetAttrs(), 1)
}

/*
func TestRawCred_AddStringAttribute(t *testing.T) {
	rc := NewRawCred()
	err := rc.AddStrAttr("Name", "John")
	assert.NoError(t, err)
	a, _ := rc.GetAttr("Name")
	assert.Equal(t, , a.internalValue())
}*/

// checks that when a duplicate parameter is created, error is
// reported.
func TestRawCred_AddDuplicate(t *testing.T) {
	c := NewRawCred(NewAttrCount(1, 0, 0))
	_ = c.AddInt64Attr("a", 10, true)
	err := c.AddInt64Attr("a", 12, false)
	assert.Error(t, err)
}

// TODO case insensitivity?

// check that we're able to fetch an attribute stored in raw credential.
func TestRawCred_GetAttribute(t *testing.T) {
	rc := NewRawCred(NewAttrCount(2, 0, 0))
	_ = rc.AddInt64Attr("test", 10, true)
	a, err := rc.GetAttr("test")
	aCheck, _ := NewInt64Attr("test", 10, true)
	assert.NoError(t, err)
	assert.EqualValues(t, aCheck, a)
}

// check that an error is raised when we're trying to access an
// attribute that does not exist in the credential.
func TestRawCred_GetAttributeInvalid(t *testing.T) {
	rc := NewRawCred(NewAttrCount(1, 0, 0))
	a, err := rc.GetAttr("test")
	assert.Error(t, err)
	assert.Nil(t, a)
}
