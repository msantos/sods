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
-module(seds).
-behaviour(gen_server).

-include_lib("kernel/src/inet_dns.hrl").
-include("seds.hrl").

-define(SERVER, ?MODULE).

-export([start_link/0, start_link/1]).
-export([config/2,privpath/1]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
        terminate/2, code_change/3]).

-record(state, {
        f,                              % forwarders map
        s,                              % socket
        d = [],                         % domains
        p = []                          % list of proxies
    }).

-record(seds, {
        q,                              % decoded DNS query
        type,                           % 'up' or 'down'
        id = 0,                         % 2 or 4 byte session ID
        forward,                        % tuple describing destination ip/port
        sum = 0,                        % byte count
        domain = [],                    % domain names
        data = []                       % base64 encoded data
    }).


start_link() ->
    start_link(?DNS_PORT).
start_link(Port) ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [Port], []).

init([Port]) ->
    Opt = case Port of
        N when N > 1024 ->
            [];
        _ ->
            {ok, FD} = procket:listen(Port, [
                {protocol, udp},
                {family, inet},
                {type, dgram}
            ]),
            [{fd, FD}]
    end,
    {ok, Socket} = gen_udp:open(Port, [
            binary,
            {active, once}
        ] ++ Opt),
    {ok, #state{
            f = config(forward, ?CFG),
            d = config(domains, ?CFG),
            s = Socket,
            p = orddict:new()
        }}.


handle_call(_Request, _From, State) ->
    {reply, ok, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

% DNS request from client
handle_info({udp, Socket, IP, Port, Data}, #state{
        s = Socket,
        d = Domains
    } = State) ->
    ok = inet:setopts(Socket, [{active, once}]),

    case decode(Data, Domains) of
        false ->
            {noreply, State};
        {#dns_rec{} = Rec, #seds{} = Query} ->
            Session = session(Query, State),
            {Proxy, Proxies} = proxy(Socket, Session, State),
            ok = seds_proxy:send(Proxy, IP, Port, Rec, {Query#seds.type, Query#seds.data}),
            {noreply, State#state{p = Proxies}}
    end;

% Session terminated
handle_info({'DOWN', _Ref, process, Pid, _Reason}, #state{
        p = Proxies
    } = State) ->
    case lists:keyfind(Pid, 2, orddict:to_list(Proxies)) of
        false ->
            error_logger:info_report([
                    {proxy_not_found, Pid},
                    {proxies, Proxies}
                ]),
            {noreply, State};
        {Key, Pid} ->
            error_logger:info_report([
                    {proxy_found, Pid},
                    {proxies, Proxies}
                ]),
            {noreply, State#state{
                    p = orddict:erase(Key, Proxies)
                }}
    end;

% WTF?
handle_info(Info, State) ->
    error_logger:error_report([{wtf, Info}]),
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.


%%%
%%% Internal Functions
%%%
proxy(Socket, {{ServerIP, ServerPort}, SessionId} = Session, #state{
        p = Proxies
    }) ->
    case orddict:find(Session, Proxies) of
        error ->
            error_logger:info_report([
                    {proxy, starting},
                    {socket, Socket},
                    {id, SessionId},

                    {serverip, ServerIP},
                    {serverport, ServerPort}
                ]),
            {ok, Pid} = seds_proxy:start_link(
                Socket,
                {ServerIP, ServerPort}
            ),
            {Pid, orddict:store(Session, Pid, Proxies)};
        {ok, Pid} ->
            error_logger:info_report([{proxy, {found, Pid}}]),
            {Pid, Proxies}
    end.

session(#seds{
        forward = {session, Forward},
        id = Id
    },
    #state{f = Map}) ->
    F = case Forward + 1 of
        N when N > length(Map) -> 1;
        N when N < 1 -> 1;
        N -> N
    end,
    {lists:nth(F, Map), Id}.

forward(Id) when is_integer(Id) ->
    <<_Opt:8, Forward:8, SessionId:16>> = <<Id:32>>,
    {{session, Forward}, SessionId}.

% mfz.wiztb.onsgmcq.40966-0.id-372571.up.p.example.com
% B64._Nonce-Sum.id-SessionId.up.Domain
decode({domain, {a, Data}}, Domains) ->
    {Base64withNonce, Session} = lists:split(string:chr(Data, $-), Data),

    B64 = string:tokens(Base64withNonce, "."),
    [Sum, "id", SessionId, "up"|Domain] = string:tokens(Session, ".-"),

    % Respond only to the configured list of domains
    Rdomain = lists:reverse(Domain),
    true = [ N || N <- Domains, lists:prefix(N, Rdomain) ] /= [],

    {Forward, Id} = forward(list_to_integer(SessionId)),

    #seds{
        type = up,
        forward = Forward,
        id = Id,
        data = lists:flatten(lists:sublist(B64, length(B64)-1)),
        sum = list_to_integer(Sum),
        domain = Domain
    };

% 0-29941.id-10498.down.s.p.example.com
% Sum-Nonce.id-SessionId.down.Domain
decode({domain, {_Type, Data}}, Domains) ->
    [Sum, _Nonce, "id", SessionId, "down"|Domain] = string:tokens(Data, ".-"),

    % Respond only to the configured list of domains
    Rdomain = lists:reverse(Domain),
    true = [ N || N <- Domains, lists:prefix(N, Rdomain) ] /= [],

    {Forward, Id} = forward(list_to_integer(SessionId)),

    #seds{
        type = down,
        forward = Forward,
        id = Id,
        sum = list_to_integer(Sum),
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
    }, Domains) ->
    decode({domain, {Type, Query}}, Domains);
decode({binary, Data}, Domains) ->
    {ok, Query} = inet_dns:decode(Data),
    {Query, decode({dns_rec, Query}, Domains)};
decode(Data, Domains) ->
    try decode({binary, Data}, Domains) of
        {error, _} ->
            false;
        Query ->
            Query
    catch
        Error:Reason ->
            error_logger:error_report([
                    {error, Error},
                    {reason, Reason}
                ]),
            false
    end.


config(Key, Cfg) ->
    {ok, Map} = file:consult(privpath(Cfg)),
    proplists:get_value(Key, Map).

privpath(Cfg) ->
    filename:join([
        filename:dirname(code:which(?MODULE)),
        "..",
        "priv",
        Cfg
    ]).

