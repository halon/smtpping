C = g++
F = -c -Wall -DBIND_8_COMPAT 
H = resolver.hpp
L = -lresolv
T = smtpping

all:
	@echo "Use 'cmake' to build this project, unless you are"
	@echo "using Mac OS X; then type 'make osx'"

osx: $T

$T: smtpping.o resolver.o
	$C $L -o $@ $^

smtpping.o: smtpping.cpp
	$C $F -o $@ $^

resolver.o: resolver.cpp
	$C $F -o $@ $^
clean:
	rm $T smtpping.o resolver.o 
