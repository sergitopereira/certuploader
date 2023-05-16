package main

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/exp/slices"
)

//go:embed cert/ZscalerRootCertificate.crt
var cert string

//go:embed cert/certBundle.pem
var certBundle string

//apps first column is windows, second is mac
var apps = map[string]string{
	//Env variables
	"openssl": "SSL_CERT_FILE",
	"curl":    "CURL_CA_BUNDLE",
	"python":  "REQUESTS_CA_BUNDLE",
	"nodejs":  "NODE_EXTRA_CA_CERTS",
	"git":     "GIT_SSL_CAPATH",
	"aws":     "AWS_CA_BUNDLE",
	//commands
	//"gcloud":   "gcloud config set core/custom_ca_certs_file {{bundle}}",
	//"composer": "composer config --global cafile {{bundle}}",
	//"npm":      "npm config set cafile {{bundle}}",
	//registry
}

//Saving logs
var Logger *log.Logger

//Location
var Location Files

type Files struct {
	Dir string
}

func (f Files) GetCert() string {
	return filepath.Join(f.Dir, "/ZscalerRootCertificate.crt")
}

func (f Files) GetCertBundle() string {
	return filepath.Join(f.Dir, "/zscalerCAbundle.pem")
}

func (f Files) GetLog() string {
	return filepath.Join(f.Dir + "/zcertlog.txt")
}

//Init will create the certificate folder this will contain the certificate, certificate bundle and any log.
func init() {
	//Create directory first.
	createdir()
	//Create logger
	file, err := os.OpenFile(Location.GetLog(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		log.Fatal(err)
	}
	//logging to stoud and file
	w := io.MultiWriter(os.Stdout, file)
	Logger = log.New(w, "", log.Ldate|log.Ltime|log.Lshortfile)
	//Saving certificate file
	certPath := Location.GetCert()
	_, err = os.Stat(certPath)
	if os.IsNotExist(err) {
		file, err := os.Create(certPath)
		if err != nil {
			Logger.Fatal(err)
		}
		defer file.Close()
		fmt.Fprintf(file, cert)
	} else {
		Logger.Println(certPath + " already exists")
	}
	//Saving certificate bundle
	bundlePath := Location.GetCertBundle()
	_, err = os.Stat(bundlePath)
	if os.IsNotExist(err) {
		file, err := os.Create(bundlePath)
		if err != nil {
			Logger.Fatal(err)
		}
		defer file.Close()
		fmt.Fprintf(file, certBundle)
		//Apending zscaler certificate to bundle.
		fmt.Fprintln(file, "")
		crt := CertPretty()
		for _, l := range crt {
			fmt.Fprintln(file, l)
		}

	} else {
		Logger.Println(bundlePath + " already exists")
	}
}

func main() {
	//Setting command and subcommand structure
	var rootCmd = &cobra.Command{Use: "zcert.exe"}
	os := runtime.GOOS
	if os == "darwin" {
		rootCmd = &cobra.Command{Use: "./zcert"}
	}
	//cmdsystem to install zscaler cert on system trust store
	var cmdSystem = &cobra.Command{
		Use:   "system",
		Short: "install the certificate on the system trust store",
		Long:  "this will use the trust store for windows or mac so browsers, and apps following ",
		Args:  cobra.MinimumNArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			InstallSystemCert()
		},
	}
	validArguments := []string{""}
	//Adding supported apps
	for k, _ := range apps {
		validArguments = append(validArguments, k)
	}
	//cmdAppsto install zscaler cert on apps that don't follow the
	var cmdApps = &cobra.Command{
		Use:       "apps [" + strings.Join(validArguments, " ") + "] ",
		ValidArgs: validArguments,
		Short:     "install the certificate on all apps that don't follow trust store unless specified",
		Long:      "apps that where certificate will be installed: " + strings.Join(validArguments, " "),
		Args:      cobra.OnlyValidArgs,
		Run: func(cmd *cobra.Command, args []string) {
			InstallApps(args)
		},
	}

	rootCmd.AddCommand(cmdSystem)
	rootCmd.AddCommand(cmdApps)
	rootCmd.CompletionOptions.HiddenDefaultCmd = true
	rootCmd.Execute()
}

func InstallSystemCert() {
	os := runtime.GOOS
	if os == "darwin" {
		Logger.Println("OSX  OS detected")
		cmd1 := "sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain " + Location.GetCert()
		Logger.Println("running command:  " + cmd1)
		cmd := exec.Command("bash", "-c", cmd1)
		err := cmd.Run()
		if err != nil {
			Logger.Println(err)
		}
	} else if os == "windows" {

		Logger.Println("Windows OS detected")
		cmd1 := `Import-Certificate  -CertStoreLocation Cert:\LocalMachine\Root -FilePath ` + Location.GetCert()
		Logger.Println("running command:  " + cmd1)
		cmd := exec.Command("powershell", "-Command", cmd1)
		err := cmd.Run()
		if err != nil {
			Logger.Println(err)
		}

	} else {
		Logger.Fatalf("OS %v not supported", os)
	}
}

func createdir() {
	home, err := os.UserHomeDir()
	if err != nil {
		log.Fatal(err)
	}
	Location.Dir = filepath.Join(home, ".zscalerCerts") //this will create a hidden directory
	log.Println(Location.Dir)
	if _, err := os.Stat(Location.Dir); os.IsNotExist(err) {
		err := os.Mkdir(Location.Dir, 0755)
		if err != nil {
			log.Fatal(err)
		}
		log.Println("Directory created")
	} else {
		log.Println("Directory already exists")
	}
}

func InstallApps(args []string) {
	all := false
	if len(args) == 0 {
		all = true
	}
	for name, cmd := range apps {
		//iterating overt available apps and checking if the apps were selected
		if slices.Contains(args, name) || all {
			//enviroment variables case
			setEnvCheck(cmd)
		}
	}
}

//this sets the enviroment variable value
func setEnvCheck(env string) {
	value := os.Getenv(env)
	if value == "" {
		Logger.Printf("Enviroment variable: %v, not set. setting...", env)
		setEnv(env)
	} else if value == Location.GetCertBundle() {
		Logger.Printf("Enviroment variable: %v, is already set to the same value. Skipping...", env)
	} else {
		Logger.Printf("Enviroment variable: %v, is currently set to: %v. Overriding with %v", env, value, Location.GetCertBundle())
		setEnv(env)
	}
}

//this sets the enviroment variable value
func setEnv(env string) {
	os := runtime.GOOS
	if os == "darwin" {
		err := SetEnvMAC(env)
		if err != nil {
			Logger.Printf("Enviroment variable: %v, not set. Error: %v", env, err)
		} else {
			Logger.Printf("Enviroment variable: %v, set with value %v", env, Location.GetCertBundle())
		}
	} else if os == "windows" {
		err := SetEnvWindows(env)
		if err != nil {
			Logger.Printf("Enviroment variable: %v, not set. Error: %v", env, err)
		} else {
			Logger.Printf("Enviroment variable: %v, set with value %v", env, Location.GetCertBundle())
		}
	} else {
		Logger.Fatalf("OS %v not supported", os)
	}
}

func SetEnvMAC(env string) error {
	//Adding new line to env variable
	cmd := "echo \"export " + env + "=" + Location.GetCertBundle() + "\" >> ~/.zshrc"
	Logger.Printf("running command: %v", cmd)
	out, err := exec.Command("bash", "-c", cmd).Output()
	if err != nil {
		return err
	}
	Logger.Printf("output from command: %s", out)
	return nil
}

func SetEnvWindows(env string) error {
	//Adding new line to env variable
	cmd := "setx " + env + " \"" + Location.GetCertBundle() + "\""
	Logger.Printf("running command: %v", cmd)
	out, err := exec.Command("cmd", cmd).Output()
	if err != nil {
		return err
	}
	Logger.Printf("output from command: %s", out)
	return nil
}

//CertPretty this returns a pem certificate prepending issuer, fingerprint, etc.
func CertPretty() []string {
	res := []string{}
	block, _ := pem.Decode([]byte(cert))
	if block == nil || block.Type != "CERTIFICATE" {
		Logger.Fatal("failed to decode PEM block certificate")
	}
	pub, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		Logger.Fatal(err)
	}
	res = append(res, "# Issuer: CN="+pub.Issuer.CommonName)
	res = append(res, "# Subject: CN="+pub.Subject.CommonName)
	res = append(res, "# Serial: "+pub.SerialNumber.String())
	md5 := md5.Sum(pub.Raw)
	sha1 := sha1.Sum(pub.Raw)
	sha256 := sha256.Sum256(pub.Raw)
	res = append(res, "# MD5 Fingerprint: "+hex.EncodeToString(md5[:]))
	res = append(res, "# SHA1 Fingerprint: "+hex.EncodeToString(sha1[:]))
	res = append(res, "# SHA256 Fingerprint: "+hex.EncodeToString(sha256[:]))
	res = append(res, cert)
	return res
}
