package cl

import "math/big"

// CredAttribute represents an attribute for the CL scheme.
type CredAttribute interface {
	setValue(interface{}) error
	internalValue() *big.Int
	getValue() interface{}
	isKnown() bool
}

// Attribute is part of a credential (RawCredential). In the case of digital identity credential,
// attributes could be for example Name, Gender, Date of Birth. In the case of a credential allowing
// access to some internet service (like electronic newspaper), attributes could be
// Type (for example only news related to politics) of the service and Date of Expiration.
type Attribute struct {
	Index       int
	Name        string
	Known       bool
	internalVal *big.Int
}

type IntAttribute struct {
	val int
	*Attribute
}

func AddIntAttribute(name string, val int) *IntAttribute {
	return &IntAttribute{
		Attribute: &Attribute{
			Name: name,
		},
	}
}

type StringAttribue struct {
	val string
	*Attribute
}

func NewAttribute(index int, name, attrType string, known bool) *Attribute {
	return &Attribute{
		Index: index,
		Name:  name,
		Type:  attrType,
		Known: known,
		Value: value,
	}
}
