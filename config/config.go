/*
 * Copyright 2017 XLAB d.o.o.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package config

import (
	"fmt"
	"math/big"

	"os"
	"path/filepath"

	"github.com/spf13/viper"
	"github.com/xlab-si/emmy/crypto/groups"
	"github.com/xlab-si/emmy/crypto/zkp/schemes/pseudonymsys"
)

// init loads the default config file
func init() {
	// set reasonable defaults
	setDefaults()

	// override defaults with configuration read from configuration file
	viper.AddConfigPath("$GOPATH/src/github.com/xlab-si/emmy/config")
	err := loadConfig("defaults", "yml")
	if err != nil {
		fmt.Println(err)
	}
}

// setDefaults sets default values for various public cryptographic parameters that need to be
// consistent between a given emmy client and emmy server.
func setDefaults() {
	/*viper.SetDefault("ip", "localhost")
	viper.SetDefault("port", 7007)
	viper.SetDefault("timeout", 5)
	viper.SetDefault("key_folder", "/tmp")*/

	viper.SetDefault("schnorr_group", map[string]string{
		"p": "16714772973240639959372252262788596420406994288943442724185217359247384753656472309049760952976644136858333233015922583099687128195321947212684779063190875332970679291085543110146729439665070418750765330192961290161474133279960593149307037455272278582955789954847238104228800942225108143276152223829168166008095539967222363070565697796008563529948374781419181195126018918350805639881625937503224895840081959848677868603567824611344898153185576740445411565094067875133968946677861528581074542082733743513314354002186235230287355796577107626422168586230066573268163712626444511811717579062108697723640288393001520781671",
		"g": "13435884250597730820988673213378477726569723275417649800394889054421903151074346851880546685189913185057745735207225301201852559405644051816872014272331570072588339952516472247887067226166870605704408444976351128304008060633104261817510492686675023829741899954314711345836179919335915048014505501663400445038922206852759960184725596503593479528001139942112019453197903890937374833630960726290426188275709258277826157649744326468681842975049888851018287222105796254410594654201885455104992968766625052811929321868035475972753772676518635683328238658266898993508045858598874318887564488464648635977972724303652243855656",
		"q": "98208916160055856584884864196345443685461747768186057136819930381973920107591",
	})

	viper.SetDefault("pseudonymsys_ca", map[string]string{
		"x": "65326558506481070730591115387915499623679021660430456972125964980023301473231",
		"y": "37526396936964061204061100652712760357856013823850948443144488667237183893571",
	})

	viper.SetDefault("pseudonymsys.org1", map[string]string{
		"h1": "11253748020267515701977135421640400742511414782332660443524776235731592618314865082641495270379529602832564697632543178140373575666207325449816651443326295587329200580969897900340682863137274403743213121482058992744156278265298975875832815615008349379091580640663544863825594755871212120449589876097254391036951735135790415340694042060640287135597503154554767593490141558733646631257590898412097094878970047567251318564175378758713497120310233239160479122314980866111775954564694480706227862890375180173977176588970220883117212300621045744043530072238840577201003052170999723878986905807102656657527667244456412473985",
		"h2": "76168773256070905782197510623595125058465077612447809025568517977679494145178174622864958684725961070073576803345724904501942931513809178875449022568661712955904784104680061168715431907736821341951579763867969478146743783132963349845621343504647834967006527983684679901491401571352045358450346417143743546169924539113192750473927517206655311791719866371386836092309758541857984471638917674114075906273800379335165008797874367104743232737728633294061064784890416168238586934819945486226202990710177343797354424869474259809902990704930592533690341526792158132580375587182781640673464871125845158432761445006356929132",
	})

	viper.SetDefault("pseudonymsys_ec.org1", map[string]string{
		"h1x": "111843344654618029419055700569023289100199029635186896671499163057944727230",
		"h1y": "63726701293868334061084235330967878003056898720773299094696019482924813137111",
		"h2x": "3836882559946612606724713122432195411371871189052450829349314418954131635804",
		"h2y": "87187568403836989661029612226711448246955830180833597642485083706252921915098",
	})
}

// loadConfig reads in the config file with configName being the name of the file (without suffix)
// and configType being "yml" or "json".
func loadConfig(configName string, configType string) error {
	viper.SetConfigName(configName)
	viper.SetConfigType(configType)

	err := viper.ReadInConfig()
	if err != nil {
		return fmt.Errorf("cannot read configuration file: %s\n", err)
	}

	return nil
}

// LoadServerPort returns the port where emmy server will be listening.
func LoadServerPort() int {
	return viper.GetInt("port")
}

// LoadServerEndpoint returns the endpoint of the emmy server where clients will be contacting it.
func LoadServerEndpoint() string {
	return viper.GetString("server")
}

// LoadTimeout returns the specified number of seconds that clients wait before giving up
// on connection to emmy server
func LoadTimeout() float64 {
	return viper.GetFloat64("timeout")
}

func LoadKeyDirFromConfig() string {
	return viper.GetString("key_folder")
}

func LoadTestdataDir() string {
	prefix := filepath.Join(os.Getenv("GOPATH"), "src", "github.com", "xlab-si", "emmy")
	return filepath.Join(prefix, viper.GetString("testdata_dir"))
}

func LoadTestKeyDirFromConfig() string {
	key_path := viper.GetString("key_folder")
	return key_path
}

// LoadSchnorrGroup attempts to create schnorr group from the parameters given in config file.
func LoadSchnorrGroup() (*groups.SchnorrGroup, error) {
	group := viper.GetStringMapString("schnorr_group")
	p, pOk := new(big.Int).SetString(group["p"], 10)
	g, gOk := new(big.Int).SetString(group["g"], 10)
	q, qOk := new(big.Int).SetString(group["q"], 10)
	if !pOk || !gOk || !qOk {
		return nil, fmt.Errorf("Cannot convert schnorr group params to big integers")
	}
	return groups.NewSchnorrGroupFromParams(p, g, q), nil
}

// LoadQRRSA attempts to construct QRRSA from the parameters given in config file.
func LoadQRRSA() (*groups.QRRSA, error) {
	qr := viper.GetStringMapString("qr")
	p, pOk := new(big.Int).SetString(qr["p"], 10)
	q, qOk := new(big.Int).SetString(qr["q"], 10)
	if !pOk || !qOk {
		return nil, fmt.Errorf("Cannot convert QRRSA params to big integers")
	}

	qrRSA, err := groups.NewQRRSA(p, q)
	if err != nil {
		return nil, fmt.Errorf("error loading QRRSA RSA group: %s", err)
	}
	return qrRSA, nil
}

// orgHasConfigData checks for presence of a given organization's configuration for pseudonymsys
// anonymous authentication scheme.
func orgHasConfigData(orgName string, ec bool) bool {
	if ec {
		return viper.IsSet(fmt.Sprintf("pseudonymsys_ec.%s", orgName))
	}
	return viper.IsSet(fmt.Sprintf("pseudonymsys.%s", orgName))
}

// LoadPseudonymsysOrgSecrets attempts to read a given organization's secret parameters provided in
// config file.
func LoadPseudonymsysOrgSecrets(orgName string) (*pseudonymsys.Key, error) {
	if !orgHasConfigData(orgName, false) {
		return nil, fmt.Errorf("mising configuration for organization %s", orgName)
	}
	org := viper.GetStringMapString(fmt.Sprintf("pseudonymsys.%s", orgName))
	s1, s1Ok := new(big.Int).SetString(org["s1"], 10)
	s2, s2Ok := new(big.Int).SetString(org["s2"], 10)
	if !s1Ok || !s2Ok {
		return nil, fmt.Errorf("Cannot convert organization's secret params to big integers")
	}
	return pseudonymsys.NewKey(s1, s2), nil
}

// LoadPseudonymsysOrgSecretsEC attempts to read a given organization's secret parameters provided
// in config file.
func LoadPseudonymsysOrgSecretsEC(orgName string) (*pseudonymsys.Key, error) {
	if !orgHasConfigData(orgName, true) {
		return nil, fmt.Errorf("mising configuration for organization %s", orgName)
	}
	org := viper.GetStringMapString(fmt.Sprintf("pseudonymsys_ec.%s", orgName))
	s1, s1Ok := new(big.Int).SetString(org["s1"], 10)
	s2, s2Ok := new(big.Int).SetString(org["s2"], 10)
	if !s1Ok || !s2Ok {
		return nil, fmt.Errorf("Cannot convert organization's secret params to big integers")
	}
	return pseudonymsys.NewKey(s1, s2), nil
}

// LoadPseudonymsysOrgPubKeys attempts to create organization's public key from the
// parameters given in config file.
func LoadPseudonymsysOrgPubKeys(orgName string) (*pseudonymsys.Key, error) {
	if !orgHasConfigData(orgName, false) {
		return nil, fmt.Errorf("mising configuration for organization %s", orgName)
	}
	org := viper.GetStringMapString(fmt.Sprintf("pseudonymsys.%s", orgName))

	h1, h1Ok := new(big.Int).SetString(org["h1"], 10)
	h2, h2Ok := new(big.Int).SetString(org["h2"], 10)
	if !h1Ok || !h2Ok {
		return nil, fmt.Errorf("Cannot convert org pub keys params to big integers")
	}

	return pseudonymsys.NewKey(h1, h2), nil
}

// LoadPseudonymsysOrgPubKeysEC attempts to create organization's EC public key from the
// parameters given in config file.
func LoadPseudonymsysOrgPubKeysEC(orgName string) (*pseudonymsys.PubKeyEC, error) {
	if !orgHasConfigData(orgName, true) {
		return nil, fmt.Errorf(fmt.Sprintf("mising configuration for organization %s", orgName))
	}
	org := viper.GetStringMapString(fmt.Sprintf("pseudonymsys_ec.%s", orgName))

	h1X, h1Xok := new(big.Int).SetString(org["h1x"], 10)
	h1Y, h1Yok := new(big.Int).SetString(org["h1y"], 10)
	h2X, h2Xok := new(big.Int).SetString(org["h2x"], 10)
	h2Y, h2Yok := new(big.Int).SetString(org["h2y"], 10)
	if !h1Xok || !h1Yok || !h2Xok || !h2Yok {
		return nil, fmt.Errorf("Cannot convert org pub keys params to big integers")
	}

	return pseudonymsys.NewOrgPubKeysEC(
		groups.NewECGroupElement(h1X, h1Y),
		groups.NewECGroupElement(h2X, h2Y)), nil
}

// LoadPseudonymsysCASecret attempts to read CA's secret parameters provided
// in config file
func LoadPseudonymsysCASecret() (*big.Int, error) {
	caSecret := viper.GetString("pseudonymsys_ca.s")
	s, sOk := new(big.Int).SetString(caSecret, 10)
	if !sOk {
		return nil, fmt.Errorf("Cannot convert CA secret key to big integer")
	}
	return s, nil
}

// LoadPseudonymsysCAPubKey attempts to create CA's public key from the
// parameters given in config file.
func LoadPseudonymsysCAPubKey() (*pseudonymsys.Key, error) {
	ca := viper.GetStringMapString("pseudonymsys_ca")
	h1, h1Ok := new(big.Int).SetString(ca["h1"], 10)
	h2, h2Ok := new(big.Int).SetString(ca["h2"], 10)
	if !h1Ok || !h2Ok {
		return nil, fmt.Errorf("Cannot convert CA pub key params to big integers")
	}
	return pseudonymsys.NewKey(h1, h2), nil
}

func LoadServiceInfo() (string, string, string) {
	serviceName := viper.GetString("service_info.name")
	serviceProvider := viper.GetString("service_info.provider")
	serviceDescription := viper.GetString("service_info.description")
	return serviceName, serviceProvider, serviceDescription
}

func LoadSessionKeyMinByteLen() int {
	return viper.GetInt("session_key_bytelen")
}

func LoadRegistrationDBAddress() string {
	return viper.GetString("registration_db_address")
}
