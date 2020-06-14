package config_test

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"testing"

	c "github.com/SimonSchneider/traefik-jwt-decode/config"

	dt "github.com/SimonSchneider/traefik-jwt-decode/decodertest"
)

var (
	claims = map[string]interface{}{
		"claim1": "claim value 1",
		"claim2": "claim value 2",
		"claim3": "claim value 3",
	}
	claimMappingString = "claim1:claimHeader1,claim2:claimHeader2"
	claimMappingMap    = map[string]string{
		"claim1": "claimHeader1",
		"claim2": "claimHeader2",
	}
)

func TestEnvClaimMappingsConfiguration(t *testing.T) {
	os.Clearenv()
	tc := dt.NewTest()
	defaultEnv(tc)
	os.Setenv(c.ClaimMappingsEnv, claimMappingString)
	validateCorrectSetup(t, tc, c.AuthHeaderDefault)
}

func TestChangingPort(t *testing.T) {
	os.Clearenv()
	tc := dt.NewTest()
	defaultEnv(tc)
	os.Setenv(c.PortEnv, "10200")
	validateCorrectSetup(t, tc, c.AuthHeaderDefault)
}

func TestChangingAuthKey(t *testing.T) {
	os.Clearenv()
	tc := dt.NewTest()
	defaultEnv(tc)
	os.Setenv(c.AuthHeaderEnv, "Somekey")
	validateCorrectSetup(t, tc, "Somekey")
}

func TestClaimMappingFile(t *testing.T) {
	os.Clearenv()
	tc := dt.NewTest()
	defaultEnv(tc)
	file, err := ioutil.TempFile(".", "config.json")
	dt.HandleByPanic(err)
	defer os.Remove(file.Name())
	json.NewEncoder(file).Encode(claimMappingMap)
	os.Setenv(c.ClaimMappingsEnv, "")
	os.Setenv(c.ClaimMappingFileEnv, file.Name())
	validateCorrectSetup(t, tc, c.AuthHeaderDefault)
}

func TestMergeClaimMappingsFileAndEnv(t *testing.T) {
	os.Clearenv()
	tc := dt.NewTest()
	defaultEnv(tc)
	file, err := ioutil.TempFile(".", "config.json")
	dt.HandleByPanic(err)
	defer os.Remove(file.Name())
	json.NewEncoder(file).Encode(map[string]string{"claim1": "claimHeader1"})
	os.Setenv(c.ClaimMappingsEnv, "claim2:claimHeader2")
	os.Setenv(c.ClaimMappingFileEnv, file.Name())
	validateCorrectSetup(t, tc, c.AuthHeaderDefault)
}

func validateCorrectSetup(t *testing.T, tc *dt.TestConfig, authKey string) {
	client := &http.Client{}
	conf := c.NewConfig()
	doneChan, l := conf.RunServer()
	port := l.Addr().(*net.TCPAddr).Port
	token := tc.NewValidToken(claims)
	req, _ := http.NewRequest("GET", fmt.Sprintf("http://localhost:%d", port), nil)
	req.Header.Set(authKey, fmt.Sprintf("Bearer %s", token))
	resp, err := client.Do(req)
	dt.HandleByPanic(err)
	dt.Report(t, resp.Header.Get("claimHeader1") != claims["claim1"], "incorrect header for claim1")
	dt.Report(t, resp.Header.Get("claimHeader2") != claims["claim2"], "incorrect header for claim2")
	dt.Report(t, resp.Header.Get("claimHeader3") != "", "incorrect header for claim2")
	err = l.Close()
	dt.HandleByPanic(err)
	<-doneChan
}

func TestFailsIfNoJwksUrlIsSet(t *testing.T) {
	os.Clearenv()
	validatePanicsWhenStarting(t)
}

func TestFailsIfIncorrectLogType(t *testing.T) {
	os.Clearenv()
	tc := dt.NewTest()
	defaultEnv(tc)
	os.Setenv(c.LogTypeEnv, "badlogtype")
	validatePanicsWhenStarting(t)
}

func TestFailsOnBadClaimEncoding(t *testing.T) {
	os.Clearenv()
	tc := dt.NewTest()
	defaultEnv(tc)
	os.Setenv(c.ClaimMappingsEnv, "badmapping")
	validatePanicsWhenStarting(t)
}

func TestFailsOnBadJwksURL(t *testing.T) {
	os.Clearenv()
	tc := dt.NewTest()
	defaultEnv(tc)
	os.Setenv(c.JwksURLEnv, "http://non-existing/.jwks.url")
	validatePanicsWhenStarting(t)
}

func TestFailsOnBadLogLevel(t *testing.T) {
	os.Clearenv()
	tc := dt.NewTest()
	defaultEnv(tc)
	os.Setenv(c.LogLevelEnv, "woa")
	validatePanicsWhenStarting(t)
}

func validatePanicsWhenStarting(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Logf("function paniced with %+v", r)
			return
		}
		t.Fatal("function did not panic")
	}()
	c.NewConfig().RunServer()
}

func defaultEnv(tc *dt.TestConfig) {
	os.Setenv(c.LogTypeEnv, "pretty")
	os.Setenv(c.JwksURLEnv, tc.JwksURL)
	os.Setenv(c.LogLevelEnv, "trace")
	os.Setenv(c.PortEnv, "0")
	os.Setenv(c.ClaimMappingsEnv, claimMappingString)
}
