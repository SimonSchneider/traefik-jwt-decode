package config_test

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"

	c "github.com/SimonSchneider/traefik-jwt-decode/config"

	dt "github.com/SimonSchneider/traefik-jwt-decode/decodertest"
)

var (
	claims = map[string]interface{}{
		"claim1":  "claim value 1",
		"claim2":  "claim value 2",
		"claim:3": "claim value 3",
	}
	claimMappingString = "claim1:claimHeader1,claim2:claimHeader2,claim:3:claimHeader3"
	claimMappingMap    = map[string]string{
		"claim1":  "claimHeader1",
		"claim2":  "claimHeader2",
		"claim:3": "claimHeader3",
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
	os.Setenv(c.ClaimMappingsEnv, "claim2:claimHeader2,claim:3:claimHeader3")
	os.Setenv(c.ClaimMappingFileEnv, file.Name())
	validateCorrectSetup(t, tc, c.AuthHeaderDefault)
}

func validateCorrectSetup(t *testing.T, tc *dt.TestConfig, authKey string) {
	conf := c.NewConfig()
	doneChan, l := conf.RunServer()
	port := l.Addr().(*net.TCPAddr).Port
	token := tc.NewValidToken(claims)
	req, _ := http.NewRequest("GET", fmt.Sprintf("http://localhost:%d", port), nil)
	req.Header.Set(authKey, fmt.Sprintf("Bearer %s", token))
	resp, err := http.DefaultClient.Do(req)
	dt.HandleByPanic(err)
	dt.Report(t, resp.Header.Get("claimHeader1") != claims["claim1"], "incorrect header for claim1")
	dt.Report(t, resp.Header.Get("claimHeader2") != claims["claim2"], "incorrect header for claim2")
	dt.Report(t, resp.Header.Get("claimHeader3") != claims["claim:3"], "incorrect header for claim:3")
	validateMetrics(t, port)
	err = l.Close()
	dt.HandleByPanic(err)
	<-doneChan
}

func validateMetrics(t *testing.T, port int) {
	metricsReq, _ := http.NewRequest("GET", fmt.Sprintf("http://localhost:%d/metrics", port), nil)
	resp, err := http.DefaultClient.Do(metricsReq)
	dt.HandleByPanic(err)
	dt.Report(t, resp.StatusCode != http.StatusOK, "metrics endpoint not accessible %d", resp.StatusCode)
	defer resp.Body.Close()
	bBody, _ := ioutil.ReadAll(resp.Body)
	body := strings.Split(string(bBody), "\n")
	metrics := []string{"traefik_jwt_decode_http_server_requests"}
	for _, metric := range metrics {
		found := false
		for _, bodyLine := range body {
			if strings.Contains(bodyLine, metric) {
				found = true
				break
			}
		}
		dt.Report(t, !found, "metrics not found %s found %s", metric, body)
	}
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
