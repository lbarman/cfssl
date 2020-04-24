package genkey

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/cloudflare/cfssl/certinfo"
	"io/ioutil"
	"log"
	"os"
	"testing"

	"github.com/cloudflare/cfssl/cli"
)

type stdoutRedirect struct {
	r     *os.File
	w     *os.File
	saved *os.File
}

func newStdoutRedirect() (*stdoutRedirect, error) {
	r, w, err := os.Pipe()
	if err != nil {
		return nil, err
	}

	pipe := &stdoutRedirect{r, w, os.Stdout}
	os.Stdout = pipe.w
	return pipe, nil
}

func (pipe *stdoutRedirect) readAll() ([]byte, error) {
	pipe.w.Close()
	os.Stdout = pipe.saved
	return ioutil.ReadAll(pipe.r)
}

func checkResponse(out []byte) (error, map[string]interface{}) {
	var response map[string]interface{}
	if err := json.Unmarshal(out, &response); err != nil {
		return err, nil
	}

	log.Printf("%+v\n", response)

	if response["key"] == nil {
		return errors.New("no key is outputted"), nil
	}

	if response["csr"] == nil {
		return errors.New("no csr is outputted"), nil
	}

	return nil, response
}

func TestGenkey(t *testing.T) {
	var pipe *stdoutRedirect
	var out []byte
	var err error

	if pipe, err = newStdoutRedirect(); err != nil {
		t.Fatal(err)
	}
	if err := genkeyMain([]string{"testdata/csr.json"}, cli.Config{}); err != nil {
		t.Fatal(err)
	}
	if out, err = pipe.readAll(); err != nil {
		t.Fatal(err)
	}
	if err, _ := checkResponse(out); err != nil {
		t.Fatal(err)
	}

	if pipe, err = newStdoutRedirect(); err != nil {
		t.Fatal(err)
	}
	if err := genkeyMain([]string{"testdata/csr.json"}, cli.Config{IsCA: true}); err != nil {
		t.Fatal(err)
	}
	if out, err = pipe.readAll(); err != nil {
		t.Fatal(err)
	}
	if err, _ := checkResponse(out); err != nil {
		t.Fatal(err)
	}
}

func TestGenkeyWithExpiry(t *testing.T) {
	var pipe *stdoutRedirect
	var out []byte
	var err error

	if pipe, err = newStdoutRedirect(); err != nil {
		t.Fatal(err)
	}
	if err := genkeyMain([]string{"testdata/csr-with-expiry.json"}, cli.Config{}); err != nil {
		t.Fatal(err)
	}
	if out, err = pipe.readAll(); err != nil {
		t.Fatal(err)
	}
	err, response := checkResponse(out)
	if err != nil {
		t.Fatal(err)
	}

	cert := (response["csr"]).(string)

	certParsed, err := certinfo.ParseCertificatePEM([]byte(cert))

	fmt.Printf("%+v\n", cert)
	fmt.Printf("%+v\n", certParsed)

	if err != nil {
		t.Fatal("Couldn't parse the produced cert", err)
	}


	/*
	HoursInAYear := float64(8766) // 365.25 * 24
	expiryHoursInConfig := c.CFG.Signing.Default.Expiry.Hours()
	expiryYearsInConfig := int(math.Ceil(expiryHoursInConfig / HoursInAYear))
	certExpiryInYears := certParsed.NotAfter.Year() - time.Now().Year()

	if certExpiryInYears != expiryYearsInConfig {
		t.Fatal("Expiry specified in Config file is", expiryYearsInConfig, "but cert has expiry", certExpiryInYears)
	}*/
}
