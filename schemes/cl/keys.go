package cl

import (
	"github.com/emmyzkp/crypto/qr"
	"math/big"
	"github.com/emmyzkp/crypto/pedersen"
	"github.com/emmyzkp/crypto/common"
	"github.com/emmyzkp/crypto/df"
	"github.com/pkg/errors"
)

type KeyPair struct {
	sec *SecKey
	Pub *PubKey
}

// SecKey is a secret key for the CL scheme.
type SecKey struct {
	RsaPrimes                  *qr.RSASpecialPrimes
	AttributesSpecialRSAPrimes *qr.RSASpecialPrimes
}

// NewSecKey accepts group g and commitment receiver cr, and returns
// new secret key for the CL scheme.
func NewSecKey(g *qr.RSASpecial, cr *df.Receiver) *SecKey {
	return &SecKey{
		RsaPrimes:                  g.GetPrimes(),
		AttributesSpecialRSAPrimes: cr.QRSpecialRSA.GetPrimes(),
	}
}

// PubKey is a public key for the CL scheme.
type PubKey struct {
	N              *big.Int
	S              *big.Int
	Z              *big.Int
	RsKnown        []*big.Int // one R corresponds to one attribute - these attributes are known to both - receiver and issuer
	RsCommitted    []*big.Int // issuer knows only commitments of these attributes
	RsHidden       []*big.Int // only receiver knows these attributes
	PedersenParams *pedersen.Params
	// the fields below are for commitments of the (committed) attributes
	N1 *big.Int
	G  *big.Int
	H  *big.Int
}

// NewPubKey accepts group g, parameters p and commitment receiver recv,
// and returns a public key for the CL scheme.
func NewPubKey(g *qr.RSASpecial, p *Params, recv *df.Receiver) (*PubKey, error) {
	S, Z, RsKnown, RsCommitted, RsHidden, err := generateQuadraticResidues(
		g, p.KnownAttrsNum, p.CommittedAttrsNum, p.HiddenAttrsNum)
	if err != nil {
		return nil, errors.Wrap(err, "error creating quadratic residues")
	}

	pp, err := pedersen.GenerateParams(p.RhoBitLen)
	if err != nil {
		return nil, errors.Wrap(err, "error creating Pedersen receiver")
	}

	return &PubKey{
		N:              g.N,
		S:              S,
		Z:              Z,
		RsKnown:        RsKnown,
		RsCommitted:    RsCommitted,
		RsHidden:       RsHidden,
		PedersenParams: pp,
		N1:             recv.QRSpecialRSA.N,
		G:              recv.G,
		H:              recv.H,
	}, nil
}

// GenerateUserMasterSecret generates a secret key that needs to be encoded into every user's credential as a
// sharing prevention mechanism.
func (k *PubKey) GenerateUserMasterSecret() *big.Int {
	return common.GetRandomInt(k.PedersenParams.Group.Q)
}

// GetContext concatenates public parameters and returns a corresponding number.
func (k *PubKey) GetContext() *big.Int {
	numbers := []*big.Int{k.N, k.S, k.Z}
	numbers = append(numbers, k.RsKnown...)
	numbers = append(numbers, k.RsCommitted...)
	numbers = append(numbers, k.RsHidden...)
	concatenated := common.ConcatenateNumbers(numbers...)
	return new(big.Int).SetBytes(concatenated)
}

// GenerateKeyPair takes and constructs a keypair containing public and
// secret key for the CL scheme.
func GenerateKeyPair(p *Params) (*KeyPair, error) {
	g, err := qr.NewRSASpecial(p.NLength / 2)
	if err != nil {
		return nil, errors.Wrap(err,"error creating RSASpecial group")
	}

	// receiver for commitments of (committed) attributes:
	commRecv, err := df.NewReceiver(p.NLength/2, p.SecParam)
	if err != nil {
		return nil, errors.Wrap(err, "error creating DF commitment receiver")
	}

	sk := NewSecKey(g, commRecv)

	pk, err := NewPubKey(g, p, commRecv)
	if err != nil {
		return nil, err
	}

	return &KeyPair{
		sec: sk,
		Pub: pk,
	}, nil
}