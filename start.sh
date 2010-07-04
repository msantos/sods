#!/bin/sh

#exec erl -pa $PWD/ebin $PWD/deps/*/ebin $PWD/deps/*/deps/*/ebin -s seds start_link
exec erl -pa $PWD/ebin $PWD/deps/*/ebin $PWD/deps/*/deps/*/ebin 
