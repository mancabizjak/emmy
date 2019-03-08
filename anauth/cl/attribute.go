package cl

import (
	"fmt"
	"math/big"
	"strconv"

	"github.com/spf13/viper"
)

// AttrCount holds the number of known, committed and
// hidden parameters.
type AttrCount struct {
	known     int
	committed int
	hidden    int
}

func NewAttrCount(known, committed, hidden int) *AttrCount {
	return &AttrCount{
		known:     known,
		committed: committed,
		hidden:    hidden,
	}
}

// CredAttr represents an attribute for the CL scheme.
type CredAttr interface {
	getValue() interface{}
	UpdateValue(interface{}) error
	internalValue() *big.Int
	setInternalValue() error
	isKnown() bool
	name() string
	String() string
}

// attr is part of a credential (RawCredential). In the case of digital identity credential,
// attributes could be for example Name, Gender, Date of Birth. In the case of a credential allowing
// access to some internet service (like electronic newspaper), attributes could be
// Type (for example only news related to politics) of the service and Date of Expiration.
type attr struct {
	Name  string
	Known bool
	val   *big.Int
}

func newAttr(name string, known bool) *attr {
	return &attr{
		Name:  name,
		Known: known,
	}
}

func (a *attr) isKnown() bool {
	return a.Known
}

func (a *attr) internalValue() *big.Int {
	return a.val
}

func (a *attr) name() string {
	return a.Name
}

func (a *attr) String() string {
	tag := "known"
	if !a.isKnown() {
		tag = "revealed"
	}
	return fmt.Sprintf("%s (%s)", a.Name, tag)
}

type Int64Attr struct {
	val int64
	*attr
}

func NewInt64Attr(name string, val int64, known bool) (*Int64Attr,
	error) {
	a := &Int64Attr{
		val:  val,
		attr: newAttr(name, known),
	}
	if err := a.setInternalValue(); err != nil {
		return nil, err
	}

	return a, nil
}

func (a *Int64Attr) setInternalValue() error {
	a.attr.val = big.NewInt(int64(a.val)) // FIXME
	return nil
}

func (a *Int64Attr) getValue() interface{} {
	return a.val
}

func (a *Int64Attr) UpdateValue(n interface{}) error {
	a.val = int64(n.(int))
	return a.setInternalValue()
}

func (a *Int64Attr) String() string {
	return fmt.Sprintf("%s, type = %T", a.attr.String(), a.val)
}

type StrAttr struct {
	val string
	*attr
}

func NewStrAttr(name, val string, known bool) (*StrAttr,
	error) {
	a := &StrAttr{
		val:  val,
		attr: newAttr(name, known),
	}
	if err := a.setInternalValue(); err != nil {
		return nil, err
	}

	return a, nil
}

func (a *StrAttr) setInternalValue() error {
	a.attr.val = new(big.Int).SetBytes([]byte(a.val)) // FIXME
	return nil
}

func (a *StrAttr) getValue() interface{} {
	return a.val
}

func (a *StrAttr) UpdateValue(s interface{}) error {
	a.val = s.(string)
	return a.setInternalValue()
}

func (a *StrAttr) String() string {
	return fmt.Sprintf("%s, type = %T", a.attr.String(), a.val)
}

// FIXME make nicer
// Hook to organization?
func ParseAttrs(v *viper.Viper) ([]CredAttr, *AttrCount, error) {
	if !v.IsSet("attributes") {
		return nil, nil, fmt.Errorf("missing attributes declaration")
	}

	attrs := make([]CredAttr, 0)
	var nKnown, nCommitted int

	specs := v.GetStringMap("attributes")
	for name, val := range specs {
		data, ok := val.(map[string]interface{})
		if !ok {
			return nil, nil, fmt.Errorf("invalid configuration")
		}

		t, ok := data["type"]
		if !ok {
			return nil, nil, fmt.Errorf("missing type specifier")
		}

		known := true
		k, ok := data["known"]
		if ok {
			res, err := strconv.ParseBool(k.(string))
			if err != nil {
				return nil, nil, fmt.Errorf("known must be true or false")
			}
			known = res
		}

		if known {
			nKnown++
		} else {
			nCommitted++
		}

		switch t {
		case "string":
			a, err := NewStrAttr(name, "", known) // FIXME
			if err != nil {
				return nil, nil, err
			}
			attrs = append(attrs, a)
		case "int64":
			a, err := NewInt64Attr(name, 0, known) // FIXME
			if err != nil {
				return nil, nil, err
			}
			attrs = append(attrs, a)
		default:
			return nil, nil, fmt.Errorf("unsupported attribute type: %s", t)
		}

	}

	// TODO hidden params
	return attrs, NewAttrCount(nKnown, nCommitted, 0), nil
}
