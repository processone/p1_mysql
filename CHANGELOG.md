# Version 1.0.26

* Make compatible with R28

# Version 1.0.24

* Add support for unix domain sockets
* Make compatible with OTP27
* Fix couple issues in binary protocol decoding

# Version 1.0.23

* Add support for sha256_password authenticaiton

# Version 1.0.22

* Add support for prepared statements

# Version 1.0.21

* Pass SSLOpts to ssl:connect

# Version 1.0.20

* Faster and more robust detection of reconnect/failed connections

# Version 1.0.19

* Switch from using Travis to Github Actions as CI

# Version 1.0.18

* Update copyright year to 2021
* add_mysql_conn always returns success, except if crashes
* Database is always 'none', as noticed by Dialyzer
* Data is always binary, as noticed by Dialyzer

# Version 1.0.17

* Update travis config

# Version 1.0.15

* Fix warnings

# Version 1.0.14

* Add abilty to use ssl connections

# Version 1.0.13

* Update copyright year

# Version 1.0.12

* Properly handle decoding of number of returned fields when there is
  more than 128 of them.

# Version 1.0.11

* Handle close even in do\_recv, this fixes potential connection being stuck after timeout

# Version 1.0.10

* Make socket close always lead to terminating p1\_mysql\_conn

# Version 1.0.9

* Add contribution guide
* Don't log errors on shutdown

# Version 1.0.8

* Add support for mysql8 and cache\_sha2\_password authentication

# Version 1.0.7

* Fix connection timeout handling

# Version 1.0.6

* Add support for ipv6 connections

# Version 1.0.5

* Fix compilation with rebar3

# Version 1.0.4

* Update coverall script

# Version 1.0.3

* Make it possible to set connect timeout

# Version 1.0.2

* accepting query as iodata() on p1_mysql_conn:squery/4 function (Felipe Ripoll)

# Version 1.0.1

* Repository is now called p1_mysql for consistency (Mickaël Rémond)
* Initial release on Hex.pm (Mickaël Rémond)
* Standard ProcessOne build chain (Mickaël Rémond)
* Setup Travis-CI and test coverage, tests still needed (Mickaël Rémond)
