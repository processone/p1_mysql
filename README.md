# p1_mysql

[![CI](https://github.com/processone/p1_mysql/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/processone/p1_mysql/actions/workflows/ci.yml)
[![Coverage Status](https://coveralls.io/repos/processone/p1_mysql/badge.svg?branch=master&service=github)](https://coveralls.io/github/processone/p1_mysql?branch=master)
[![Hex version](https://img.shields.io/hexpm/v/p1_mysql.svg "Hex version")](https://hex.pm/packages/p1_mysql)

p1_mysql is a pure Erlang MySQL driver.

## Building

MySQL driver can be build as follow:

    make

It is a rebar-compatible OTP application. Alternatively, you can build
it with rebar:

    rebar compile

## Development

### Test

#### Unit test

You can run eunit test with the command:

    $ rebar eunit
