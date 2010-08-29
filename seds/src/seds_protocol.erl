%% Copyright (c) 2010, Michael Santos <michael.santos@gmail.com>
%% All rights reserved.
%%
%% Redistribution and use in source and binary forms, with or without
%% modification, are permitted provided that the following conditions
%% are met:
%%
%% Redistributions of source code must retain the above copyright
%% notice, this list of conditions and the following disclaimer.
%%
%% Redistributions in binary form must reproduce the above copyright
%% notice, this list of conditions and the following disclaimer in the
%% documentation and/or other materials provided with the distribution.
%%
%% Neither the name of the author nor the names of its contributors
%% may be used to endorse or promote products derived from this software
%% without specific prior written permission.
%%
%% THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
%% "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
%% LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
%% FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
%% COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
%% INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
%% BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
%% LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
%% CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
%% LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
%% ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
%% POSSIBILITY OF SUCH DAMAGE.
-module(seds_protocol).

-include_lib("kernel/src/inet_dns.hrl").
-include("seds.hrl").

-export([decode/2, session/2]).


session(#seds{
        forward = {session, Forward},
        id = Id
    },
    #map{f = Map}) ->
    F = case Forward + 1 of
        N when N > length(Map) -> 1;
        N when N < 1 -> 1;
        N -> N
    end,
    {lists:nth(F, Map), Id};
session(#seds{
        forward = {forward, Forward},
        id = Id
    }, #map{}) ->
    {Forward, Id}.

forward({_IP, _Port} = Forward) ->
    {forward, Forward};
forward(Id) when is_integer(Id) ->
    <<_Opt:8, Forward:8, SessionId:16>> = <<Id:32>>,
    {{session, Forward}, SessionId}.


% mfz.wiztb.onsgmcq.40966-0.id-372571.u.192.168.100.101-2222.x.example.com
% B64._Nonce-Sum.id-SessionId.u.IP1.IP2.IP3.IP4-Port.x.Domain
decode({domain, {a, [Base64Nonce, Sum, "id", SessionId, "u",
                IP1, IP2, IP3, IP4, Port, "x"|Domain]}},
    #map{d = Domains, acf = true, acl = ACL}) ->

    IP = makeaddr({IP1,IP2,IP3,IP4}),

    true = check_dn(Domain, Domains),
    true = check_acl(IP, ACL),

    B64 = string:tokens(Base64Nonce, "."),
    Forward = forward({IP, list_to_integer(Port)}),

    #seds{
        type = up,
        forward = Forward,
        id = SessionId,
        data = lists:flatten(lists:sublist(B64, length(B64)-1)),
        sum = list_to_integer(Sum),
        domain = Domain
    };
decode({domain, {a, [Base64Nonce, Sum, "id", SessionId, "u",
                IP1, IP2, IP3, IP4, "x"|Domain]}},
    #map{d = Domains, acf = true, acl = ACL}) ->

    IP = makeaddr({IP1,IP2,IP3,IP4}),

    true = check_dn(Domain, Domains),
    true = check_acl(IP, ACL),

    B64 = string:tokens(Base64Nonce, "."),
    Forward = forward({IP, 22}),

    #seds{
        type = up,
        forward = Forward,
        id = SessionId,
        data = lists:flatten(lists:sublist(B64, length(B64)-1)),
        sum = list_to_integer(Sum),
        domain = Domain
    };

% mfz.wiztb.onsgmcq.40966-0.id-372571.up.p.example.com
% B64._Nonce-Sum.id-SessionId.up.Domain
decode({domain, {a, [Base64Nonce, Sum, "id", SessionId, "up"|Domain]}},
    #map{d = Domains}) ->
    true = check_dn(Domain, Domains),

    B64 = string:tokens(Base64Nonce, "."),
    {Forward, Id} = forward(list_to_integer(SessionId)),

    #seds{
        type = up,
        forward = Forward,
        id = Id,
        data = lists:flatten(lists:sublist(B64, length(B64)-1)),
        sum = list_to_integer(Sum),
        domain = Domain
    };

% 0-29941.id-10498.d.192.168.100.101.s.p.example.com
% Sum-Nonce.id-SessionId.d.IP1.IP2.IP3.IP4.Domain
%
% 0-29941.id-10498.d.192.168.100.101-2222.x.p.example.com
% Sum-Nonce.id-SessionId.d.IP1.IP2.IP3.IP4-Port.x.Domain
decode({domain, {_Type, [Sum, _Nonce, "id", SessionId, "d",
                IP1, IP2, IP3, IP4, Port, "x"|Domain]}},
        #map{d = Domains, acf = true, acl = ACL}) ->

    IP = makeaddr({IP1,IP2,IP3,IP4}),

    true = check_dn(Domain, Domains),
    true = check_acl(IP, ACL),

    Forward = forward({IP, list_to_integer(Port)}),

    #seds{
        type = down,
        forward = Forward,
        id = SessionId,
        sum = list_to_sum(Sum),
        domain = Domain
    };
decode({domain, {_Type, [Sum, _Nonce, "id", SessionId, "d",
                IP1, IP2, IP3, IP4, "x"|Domain]}}, 
        #map{d = Domains, acf = true, acl = ACL}) ->

    IP = makeaddr({IP1,IP2,IP3,IP4}),

    true = check_dn(Domain, Domains),
    true = check_acl(IP, ACL),

    Forward = forward({IP, 22}),

    #seds{
        type = down,
        forward = Forward,
        id = SessionId,
        sum = list_to_sum(Sum),
        domain = Domain
    };

% 0-29941.id-10498.down.s.p.example.com
% Sum-Nonce.id-SessionId.down.Domain
decode({domain, {_Type, [Sum, _Nonce, "id", SessionId, "down"|Domain]}},
    #map{d = Domains}) ->
    true = check_dn(Domain, Domains),

    {Forward, Id} = forward(list_to_integer(SessionId)),

    #seds{
        type = down,
        forward = Forward,
        id = Id,
        sum = list_to_sum(Sum),
        domain = Domain
    };

decode({dns_rec, #dns_rec{
            header = #dns_header{
                qr = false,
                opcode = 'query'
            },
            qdlist = [#dns_query{
                    domain = Query,
                    type = Type,
                    class = in
                }|_]
        }
    }, State) ->
    {Prefix, Session} = lists:split(string:chr(Query, $-), Query),
    decode({domain, {Type, [Prefix|string:tokens(Session, ".-")]}}, State);

decode({IP, Port, Data}, State) ->
    {ok, Query} = inet_dns:decode(Data),
    seds:send({IP, Port, Query}, decode({dns_rec, Query}, State)).

makeaddr({IP1,IP2,IP3,IP4}) when is_list(IP1), is_list(IP2), is_list(IP3), is_list(IP4) ->
    {list_to_integer(IP1), list_to_integer(IP2), list_to_integer(IP3), list_to_integer(IP4)}.

% Respond only to the configured list of domains
check_dn(Domain, Domains) ->
    [ N || N <- Domains, lists:suffix(N, Domain) ] /= [].

check_acl({IP1,IP2,IP3,IP4}, ACL) ->
    [ N || N <- ACL, lists:prefix(N, [IP1,IP2,IP3,IP4]) ] == [].

% Remove the trailing dash and convert to an integer
list_to_sum(N) when is_list(N) ->
    list_to_integer(lists:reverse(tl(lists:reverse(N)))).

