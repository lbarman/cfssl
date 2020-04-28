// cfssljson splits out JSON with cert, csr, and key fields to separate
// files.
package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/cloudflare/cfssl/cli/version"
	"io/ioutil"
	"os"
)

func readFile(filespec string) ([]byte, error) {
	if filespec == "-" {
		return ioutil.ReadAll(os.Stdin)
	}
	return ioutil.ReadFile(filespec)
}

func writeFile(filespec, contents string, perms os.FileMode) {
	err := ioutil.WriteFile(filespec, []byte(contents), perms)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

// ResponseMessage represents the format of a CFSSL writeOutput for an error or message
type ResponseMessage struct {
	Code    int    `json:"int"`
	Message string `json:"message"`
}

// Response represents the format of a CFSSL writeOutput
type Response struct {
	Success  bool                   `json:"success"`
	Result   map[string]interface{} `json:"result"`
	Errors   []ResponseMessage      `json:"errors"`
	Messages []ResponseMessage      `json:"messages"`
}

type outputFile struct {
	Filename string
	Contents string
	IsBinary bool
	Perms    os.FileMode
}

func writeErrorAndExit(formatString string, arguments ...interface{}) {
	fmt.Fprintf(os.Stderr, formatString, arguments...)
	os.Exit(1)
}

func main() {
	bare := flag.Bool("bare", false, "the response from CFSSL is not wrapped in the API standard response")
	inFile := flag.String("f", "-", "JSON input")
	stdoutOutput := flag.Bool("stdout", false, "output the response instead of saving to a file")
	jsonOutput := flag.Bool("json", false, "output the response as JSON. Implies -stdout")
	printVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *printVersion {
		fmt.Printf("%s", version.FormatVersion())
		return
	}

	var baseName string
	if flag.NArg() == 0 {
		baseName = "cert"
	} else {
		baseName = flag.Arg(0)
	}

	fileData, err := readFile(*inFile)
	if err != nil {
		writeErrorAndExit("Failed to read input: %v\n", err)
	}

	if *jsonOutput {
		*stdoutOutput = true
	}

	writeOutput(baseName, fileData, *bare, *stdoutOutput, *jsonOutput)
}

func writeOutput(baseName string, fileData []byte, bare, stdoutOutput, jsonOutput bool) {

	var input = map[string]interface{}{}
	var outs []outputFile
	var cert string
	var key string
	var csr string

	if bare {
		err := json.Unmarshal(fileData, &input)
		if err != nil {
			writeErrorAndExit("Failed to parse JSON: %v\n", string(fileData))
		}
	} else {
		var response Response
		err := json.Unmarshal(fileData, &response)
		if err != nil {
			writeErrorAndExit("Failed to parse input: %v\n", err)
		}

		if !response.Success {
			fmt.Fprintf(os.Stderr, "Request failed:\n")
			for _, msg := range response.Errors {
				fmt.Fprintf(os.Stderr, "\t%s\n", msg.Message)
			}
			os.Exit(1)
		}

		input = response.Result
	}

	if contents, ok := input["cert"]; ok {
		cert = contents.(string)
	} else if contents, ok = input["certificate"]; ok {
		cert = contents.(string)
	}
	if cert != "" {
		outs = append(outs, outputFile{
			Filename: baseName + ".pem",
			Contents: cert,
			Perms:    0664,
		})
	}

	if contents, ok := input["key"]; ok {
		key = contents.(string)
	} else if contents, ok = input["private_key"]; ok {
		key = contents.(string)
	}
	if key != "" {
		outs = append(outs, outputFile{
			Filename: baseName + "-key.pem",
			Contents: key,
			Perms:    0600,
		})
	}

	if contents, ok := input["encrypted_key"]; ok {
		encKey := contents.(string)
		outs = append(outs, outputFile{
			Filename: baseName + "-key.enc",
			Contents: encKey,
			IsBinary: true,
			Perms:    0600,
		})
	}

	if contents, ok := input["csr"]; ok {
		csr = contents.(string)
	} else if contents, ok = input["certificate_request"]; ok {
		csr = contents.(string)
	}
	if csr != "" {
		outs = append(outs, outputFile{
			Filename: baseName + ".csr",
			Contents: csr,
			Perms:    0644,
		})
	}

	if result, ok := input["result"].(map[string]interface{}); ok {
		if bundle, ok := result["bundle"].(map[string]interface{}); ok {

			// if we've gotten this deep then we're trying to parse out
			// a bundle, now we fail if we can't find the keys we need.

			certificateBundle, ok := bundle["bundle"].(string)
			if !ok {
				writeErrorAndExit("inner bundle parsing failed!\n")
			}
			rootCertificate, ok := bundle["root"].(string)
			if !ok {
				writeErrorAndExit("root parsing failed!\n")
			}
			outs = append(outs, outputFile{
				Filename: baseName + "-bundle.pem",
				Contents: certificateBundle + "\n" + rootCertificate,
				Perms:    0644,
			})
			outs = append(outs, outputFile{
				Filename: baseName + "-root.pem",
				Contents: rootCertificate,
				Perms:    0644,
			})
		}
	}

	if contents, ok := input["ocspResponse"]; ok {
		//ocspResponse is base64 encoded
		resp, err := base64.StdEncoding.DecodeString(contents.(string))
		if err != nil {
			writeErrorAndExit("Failed to parse ocspResponse: %v\n", err)
		}
		outs = append(outs, outputFile{
			Filename: baseName + "-response.der",
			Contents: string(resp),
			IsBinary: true,
			Perms:    0644,
		})
	}

	if jsonOutput {
		jsonOutputDict := make(map[string]string)
		for _, outputFile := range outs {
			if outputFile.IsBinary {
				outputFile.Contents = base64.StdEncoding.EncodeToString([]byte(outputFile.Contents))
			}
			jsonOutputDict[outputFile.Filename] = outputFile.Contents
		}

		jsonData, err := json.Marshal(jsonOutputDict)
		if err != nil {
			writeErrorAndExit("Failed to marshal to JSON the following data: %v\n", jsonOutputDict)
		}
		fmt.Fprintln(os.Stdout, string(jsonData))
	} else {
		for _, outputFile := range outs {
			if stdoutOutput {
				if outputFile.IsBinary {
					outputFile.Contents = base64.StdEncoding.EncodeToString([]byte(outputFile.Contents))
				}
				fmt.Fprintf(os.Stdout, "%s\n", outputFile.Contents)
			} else {
				writeFile(outputFile.Filename, outputFile.Contents, outputFile.Perms)
			}
		}
	}
}
