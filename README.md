# Certuploader

certuploader/zcert is a CLI tool that allows you to install the zscaler Certificate authority in tools that don't use the system trust store. 


## Installation

Feel free to compile the code or download the executables for your OS from this repo.


## Usage


Mac 

```console
Usage:
  ./zcert [command]

Available Commands:
  apps        install the certificate on all apps that don't dollow trust store unless specified
  help        Help about any command
  system      install the certificate on the system trust store

Flags:
  -h, --help   help for ./zcert
```

Windows

```console
Usage:
  ./zcert.exe [command]

Available Commands:
  apps        install the certificate on all apps that don't dollow trust store unless specified
  help        Help about any command
  system      install the certificate on the system trust store

Flags:
  -h, --help   help for ./zcert
```

## Contributing

Pull requests are welcome. For major changes, please open an issue first
to discuss what you would like to change.

Please make sure to update tests as appropriate.

## License

[MIT](https://choosealicense.com/licenses/mit/)