package cl

import (
	"math/big"
)

// CredAttribute represents an attribute for the CL scheme.
type CredAttribute interface {
	getValue() interface{}
	updateValue(interface{}) error
	internalValue() *big.Int
	setInternalValue() error
	isKnown() bool
	name() string
}

// Attribute is part of a credential (RawCredential). In the case of digital identity credential,
// attributes could be for example Name, Gender, Date of Birth. In the case of a credential allowing
// access to some internet service (like electronic newspaper), attributes could be
// Type (for example only news related to politics) of the service and Date of Expiration.
type Attribute struct {
	//Index int
	Name  string
	Known bool
	val   *big.Int
}

func newAttribute(name string, known bool) *Attribute { //index int,
	return &Attribute{
		Name:  name,
		Known: known,
	}
}

func (a *Attribute) isKnown() bool {
	return a.Known
}

func (a *Attribute) internalValue() *big.Int {
	return a.val
}

func (a *Attribute) name() string {
	return a.Name
}

type IntAttribute struct {
	val int
	*Attribute
}

func NewIntAttribute(name string, val int, known bool) (*IntAttribute,
	error) {
	a := &IntAttribute{
		val:       val,
		Attribute: newAttribute(name, known),
	}
	if err := a.setInternalValue(); err != nil {
		return nil, err
	}

	return a, nil
}

func (a *IntAttribute) setInternalValue() error {
	a.Attribute.val = big.NewInt(int64(a.val)) // FIXME
	return nil
}

func (a *IntAttribute) getValue() interface{} {
	return a.val
}

func (a *IntAttribute) updateValue(n interface{}) error {
	a.val = n.(int)
	return a.setInternalValue()
}

type StringAttribute struct {
	val string
	*Attribute
}

func NewStringAttribute(name, val string, known bool) (*StringAttribute,
	error) {
	a := &StringAttribute{
		val:       val,
		Attribute: newAttribute(name, known),
	}
	if err := a.setInternalValue(); err != nil {
		return nil, err
	}

	return a, nil
}

func (a *StringAttribute) setInternalValue() error {
	a.Attribute.val = new(big.Int).SetBytes([]byte(a.val)) // FIXME
	return nil
}

func (a *StringAttribute) getValue() interface{} {
	return a.val
}

func (a *StringAttribute) updateValue(s interface{}) error {
	a.val = s.(string)
	return a.setInternalValue()
}
