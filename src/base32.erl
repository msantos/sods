%% Taken from eadc-hub (http://github.com/JLarky/eadc-hub)
%% http://github.com/JLarky/eadc-hub/blob/master/src/eadc_utils.erl
-module(base32).
-author('jlarky@gmail.com').

-export([b32/1, encode/1,unb32/1, decode/1 ]).


%% @spec b32(integer()) -> [base32char()]
%% @doc returns base32 character corresponding to V like 1 -> 'B', 31 -> '7'.
%% V is integer from 0 to 31
%% @see unb32/1
b32(V) when V < 0 -> % wrong argument
    throw({b32,wrong_argument, V});
b32(V) when V < 26 ->
    [V+65];
b32(V) when V < 32 ->
    [V+24]; % V-26+48+2
b32(V) when is_integer(V) ->
    b32_(V, "").

b32_(0, Buf) ->
    Buf;
b32_(V, Buf) ->
    [A]=b32(V rem 32),
    b32_(V bsr 5, [A|Buf]).

%% @spec encode(string()) -> base32string()
%% @doc returns base32 encoded string of String
%% @see decode/1
encode(String) ->
    lists:reverse(encode_(list_to_binary(String), _Out=[])).

encode_(Bin, Out) ->
    case Bin of
	<<>> ->
	    Out;
	<<A:1>> ->
	    [B]=b32(A bsl 4),[B|Out];
	<<A:2>> ->
	    [B]=b32(A bsl 3),[B|Out];
	<<A:3>> ->
	    [B]=b32(A bsl 2),[B|Out];
	<<A:4>> ->
	    [B]=b32(A bsl 1),[B|Out];
	Bin ->
	    <<A:5, T/bitstring>>=Bin,
	    [B]=b32(A),encode_(T, [B|Out])
    end.

%% @spec unb32(base32char()) -> integer()
%% @doc A=unb32(b32(A))
%% @see b32/1
unb32([V]) when ((V >= $A) and (V =< $Z)) ->
    V-$A;
unb32([V]) when ((V >= $2) and (V =< $7)) ->
    V-$2+26;
unb32([V]) ->
    throw({badarg, [V]});
unb32(String=[_|_]) ->
    lists:foldl(fun(Char, Acc) ->
			Acc*32+unb32([Char])
		end, 0, String).

%% @spec decode(base32string()) -> string()
%% @doc returns base32 decoded string of String
%% @see encode/1
decode(String) ->
    Bits=lists:foldl(fun(Elem, Acc) ->
			     A= unb32([Elem]),
			     New= <<Acc/bitstring, A:5>>,
			     New
		     end, <<>>, String),
    decode_(Bits, _Out=[]).

decode_(<<>>, Out) ->
    Out;
decode_(Bits, Out) ->
    case Bits of
	<<Head:8, Rest/bitstring>> ->
	    decode_(Rest, Out++[Head]);
	<<0:1>> -> Out;
	<<0:2>> -> Out;
	<<0:3>> -> Out;
	<<0:4>> -> Out;
	<<0:5>> -> Out;
	<<0:6>> -> Out;
	<<0:7>> -> Out;
	<<H:1>> -> Out++[H bsl 7];
	<<H:2>> -> Out++[H bsl 6];
	<<H:3>> -> Out++[H bsl 5];
	<<H:4>> -> Out++[H bsl 4];
	<<H:5>> -> Out++[H bsl 3];
	<<H:6>> -> Out++[H bsl 2];
	<<H:7>> -> Out++[H bsl 1]
    end.

