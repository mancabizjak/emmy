package cl

import (
	"fmt"
	"math/big"
)

// RawCred represents a credential to be used by application that
// executes the scheme to prove possesion of an anonymous credential.
type RawCred struct {
	attrs       map[int]CredAttr
	attrIndices map[string]int
	attrCount   *AttrCount
}

func NewRawCred(c *AttrCount) *RawCred {
	return &RawCred{
		attrs:       make(map[int]CredAttr),
		attrIndices: make(map[string]int),
		attrCount:   c,
	}
}

func (c *RawCred) GetAttr(name string) (CredAttr, error) {
	i, ok := c.attrIndices[name]
	if !ok {
		return nil, fmt.Errorf("no attribute %s in this credential", name)
	}
	return c.attrs[i], nil
}

func (c *RawCred) AddStrAttr(name, val string, known bool) error {
	if err := c.validateAttr(name, known); err != nil {
		return err
	}

	i := len(c.attrs)
	a, err := NewStrAttr(name, val, known)
	if err != nil {
		return err
	}
	c.insertAttr(i, a)
	return nil
}

func (c *RawCred) AddInt64Attr(name string, val int64, known bool) error {
	if err := c.validateAttr(name, known); err != nil {
		return err
	}

	i := len(c.attrs)
	a, err := NewInt64Attr(name, val, known)
	if err != nil {
		return err
	}
	c.insertAttr(i, a)
	return nil
}

// GetKnownVals returns *big.Int values of known attributes.
// The returned elements are ordered by attribute's index.
func (c *RawCred) GetKnownVals() []*big.Int {
	var values []*big.Int
	for i := 0; i < len(c.attrs); i++ { // avoid range to have attributes in proper order
		attr := c.attrs[i]
		if attr.isKnown() {
			values = append(values, attr.internalValue())
		}
	}

	return values
}

// GetCommittedVals returns *big.Int values of committed attributes.
// The returned elements are ordered by attribute's index.
func (c *RawCred) GetCommittedVals() []*big.Int {
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

func (c *RawCred) GetAttrs() map[int]CredAttr {
	return c.attrs
}

func (c *RawCred) insertAttr(i int, a CredAttr) {
	c.attrIndices[a.name()] = i
	c.attrs[i] = a
}

func (c *RawCred) validateAttr(name string, known bool) error {
	if known && len(c.GetKnownVals()) >= c.attrCount.known {
		return fmt.Errorf("known attributes exhausted")
	}

	if !known && len(c.GetCommittedVals()) >= c.attrCount.committed {
		return fmt.Errorf("committed attributes exhausted")
	}

	if name == "" {
		return fmt.Errorf("attribute's name cannot be empty")
	}

	if c.hasAttr(name) {
		return fmt.Errorf("duplicate attribute, ignoring")
	}

	return nil
}

func (c *RawCred) hasAttr(name string) bool {
	for _, a := range c.attrs {
		if name == a.name() {
			return true
		}
	}

	return false
}
