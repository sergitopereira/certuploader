package main

import (
	_ "embed"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

//go:embed cert/ZscalerRootCertificate.crt
var cert string

func createdir() string {

	home, _ := os.UserHomeDir()
	full_path := filepath.Join(home, ".zscaler_cert")
	log.Println(full_path)
	if _, err := os.Stat(full_path); os.IsNotExist(err) {

		os.Mkdir(full_path, 0755)
		log.Println("Directory created")
	} else {
		log.Println("Directory already exists")
	}
	return full_path
}

func main() {

	destination := createdir()
	file_path := filepath.Join(destination, "ZscalerRootCertificate.crt")
	_, err := os.Stat(file_path)
	if os.IsNotExist(err) {
		file, _ := os.Create(file_path)
		defer file.Close()
		fmt.Fprintf(file, cert)

	} else {
		log.Println("ZscalerRootCertificate.crt already exists")
	}
	os := runtime.GOOS
	if os == "darwin" {
		log.Println("OSX  OS detected")
		cmd1 := "sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain " + file_path
		log.Println("running command:  " + cmd1)
		cmd := exec.Command("bash", "-c", cmd1)
		err := cmd.Run()
		if err != nil {
			fmt.Println(err)
		}
	} else if os == "windows" {

		log.Println("Windows OS detected")
		cmd1 := `Import-Certificate  -CertStoreLocation Cert:\LocalMachine\Root -FilePath ` + file_path
		log.Println("running command:  " + cmd1)
		cmd := exec.Command("powershell", "-Command", cmd1)
		err := cmd.Run()
		if err != nil {
			fmt.Println(err)
		}

	}

}
