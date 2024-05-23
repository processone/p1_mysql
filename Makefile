REBAR ?= rebar

all: src

src:
	$(REBAR) compile

clean:
	$(REBAR) clean

xref: all
	$(REBAR) xref

.PHONY: clean src
