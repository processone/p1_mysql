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
