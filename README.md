# btc_address_parser
Loads all addresses from local bitcoin blockchain data

# license
MIT

# dependencies
OpenSSL

# build 
```
git clone https://github.com/gladcow/btc_address_parser
cd btc_address_parser
cmake .
make
```
# usage
```
addr_parser [-m|-t|-r] [-p db_path] [-o output_file]
where
-m - parse BTC mainnet data, default option
-t - parse BTC testnet data
-r - parse BTC regtest data
db_path - path to the directory with block files (e.g. ${HOME}/.bitcoin/blocks),  default value is current directory
output_file - file to write parsed addresses, default value addresses.txt
```

