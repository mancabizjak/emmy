package cl

import (
	"fmt"
	"math/big"
)

// RawCredential represents a credential to be used by application that
// executes the scheme to prove possesion of an anonymous credential.
type RawCred struct {
	attrs           map[int]CredAttribute
	attrNameToIndex map[string]int
}

func NewRawCred() *RawCred {
	return &RawCred{
		attrs:           make(map[int]CredAttribute),
		attrNameToIndex: make(map[string]int),
	}
}

func (c *RawCred) GetAttribute(name string) (CredAttribute, error) {
	i, ok := c.attrNameToIndex[name]
	if !ok {
		return nil, fmt.Errorf("no attribute %s in this credential", name)
	}
	return c.attrs[i], nil
}

func (c *RawCred) InsertAttribute(i int, a CredAttribute) {
	c.attrNameToIndex[a.name()] = i
	c.attrs[i] = a
}

func (c *RawCred) AddStringAttribute(name, val string, known bool) error {
	if c.attrAlreadyPresent(name) {
		return fmt.Errorf("duplicate attribute, ignoring")
	}
	i := len(c.attrs)
	a, err := NewStringAttribute(name, val, known)
	if err != nil {
		return err
	}
	c.InsertAttribute(i, a)
	return nil
}

func (c *RawCred) AddIntAttribute(name string, val int, known bool) error {
	if c.attrAlreadyPresent(name) {
		return fmt.Errorf("duplicate attribute, ignoring")
	}
	i := len(c.attrs)
	a, err := NewIntAttribute(name, val, known)
	if err != nil {
		return err
	}
	c.InsertAttribute(i, a)
	return nil
}

// GetKnownValues returns *big.Int values of known attributes.
// The returned elements are ordered by attribute's index.
func (c *RawCred) GetKnownValues() []*big.Int {
	var values []*big.Int
	for i := 0; i < len(c.attrs); i++ { // avoid range to have attributes in proper order
		attr := c.attrs[i]
		if attr.isKnown() {
			values = append(values, attr.internalValue())
		}
	}

	return values
}

// GetCommittedValues returns *big.Int values of committed attributes.
// The returned elements are ordered by attribute's index.
func (c *RawCred) GetCommittedValues() []*big.Int {
	var values []*big.Int
	for i := 0; i < len(c.attrs); i++ { // avoid range to have attributes in
		// proper order
		attr := c.attrs[i]
		if !attr.isKnown() {
			values = append(values, attr.internalValue())
		}
	}

	return values
}

func (c *RawCred) GetAttributes() map[int]CredAttribute {
	return c.attrs
}

func (c *RawCred) attrAlreadyPresent(name string) bool {
	for _, a := range c.attrs {
		if name == a.name() {
			return true
		}
	}

	return false
}
