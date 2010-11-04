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
-module(seds_proxy).
-behaviour(gen_fsm).

-include_lib("kernel/src/inet_dns.hrl").
-include("seds.hrl").

-record(state, {
        ip,
        port,
        dnsfd,          % dns server socket
        s,              % proxied socket

        sum_up = 0,     % number of bytes sent to server
        sum_down = 0,   % number of bytes received from server
        buf = [],       % last packet sent (for resend)
        data = [<<>>]   % list of binaries: data returned by proxied server
    }).


-define(MAXDATA, 110).

% Interface
-export([send/5]).
-export([start_link/2]).
-export([label/1]).
% States
-export([connect/2,proxy/2]).
% Behaviours
-export([init/1, handle_event/3, handle_sync_event/4,
        handle_info/3, terminate/3, code_change/4]).


%%--------------------------------------------------------------------
%%% Interface
%%--------------------------------------------------------------------
send(Pid, IP, Port, #dns_rec{} = Query, {up, Sum, Data}) when is_pid(Pid) ->
    gen_fsm:send_event(Pid, {up, IP, Port, Query, Sum, Data});
send(Pid, IP, Port, #dns_rec{} = Query, {down, Sum, _}) when is_pid(Pid) ->
    gen_fsm:send_event(Pid, {down, IP, Port, Query, Sum}).

%%--------------------------------------------------------------------
%%% Behaviours
%%--------------------------------------------------------------------
start_link(Socket, {ServerIP, ServerPort}) ->
    {ok, Pid} = gen_fsm:start(?MODULE, [
            Socket,
            {ServerIP, ServerPort}
        ], []),
    erlang:monitor(process, Pid),
    {ok, Pid}.

init([DNSSocket, {ServerIP, ServerPort}]) ->
    process_flag(trap_exit, true),
    {ok, connect, #state{
            dnsfd = DNSSocket,
            ip = ServerIP,
            port = ServerPort
        }, 0}.


handle_event(_Event, StateName, State) ->
    {next_state, StateName, State}.

handle_sync_event(_Event, _From, StateName, State) ->
    {next_state, StateName, State}.


%%
%% State: proxy
%%

% From server
handle_info({tcp, Socket, Data}, proxy, #state{s = Socket} = State) ->
    {next_state, proxy, State#state{
            data = [Data|State#state.data]
        }, ?PROXY_TIMEOUT};

% Connection closed
handle_info({tcp_closed, Socket}, proxy, #state{s = Socket} = State) ->
    {stop, shutdown, State}.

terminate(Reason, StateName, #state{
        ip = IP,
        port = Port,
        sum_up = Up,
        sum_down = Down
    }) ->
    error_logger:info_report([
            {session_end, {IP, Port}},
            {bytes_sent, Up},
            {bytes_rcvd, Down},
            {state, StateName},
            {reason, Reason}
        ]),
    ok.

code_change(_OldVsn, StateName, State, _Extra) ->
    {ok, StateName, State}.


%%--------------------------------------------------------------------
%%% States
%%--------------------------------------------------------------------

%%
%% connect
%%
connect(timeout, #state{ip = IP, port = Port} = State) ->
    {ok, Socket} = gen_tcp:connect(IP, Port, [
            binary,
            {packet, 0},
            {active, once}
        ], 5000),
    {next_state, proxy, State#state{s = Socket}}.


%%
%% proxy
%%

% client sent data to be forwarded to server
proxy({up, IP, Port, Rec, ClientSum, Data},
    #state{
        sum_up = Sum,
        dnsfd = DNSSocket,
        s = Socket
    } = State) ->

    Payload = base32:decode(string:to_upper(Data)),
    Sum1 = Sum + length(Payload),

    case response(up, ClientSum, Sum, Rec) of
        error ->
            {stop, {up, out_of_sync}, State};
        duplicate ->
            error_logger:info_report([{dropping, {IP, Port}}]),
            {next_state, proxy, State, ?PROXY_TIMEOUT};
        Packet ->
%            error_logger:info_report([
%                {direction, up},
%                {dns_query, Packet}
%            ]),
            ok = gen_tcp:send(Socket, Payload),
            ok = gen_udp:send(DNSSocket, IP, Port, Packet),
            {next_state, proxy, State#state{sum_up = Sum1},
                ?PROXY_TIMEOUT}
    end;

% client requested pending data from server
proxy({down, IP, Port,
        #dns_rec{
            qdlist = [#dns_query{
                    type = Type
                }|_]} = Rec, ClientSum},
        #state{
            sum_down = Sum,
            dnsfd = DNSSocket,
            s = Socket,
            data = Data,
            buf = Buf
        } = State) ->

    {Payload, Size, Rest} = data(Type, Data),

    case response({down, Payload}, ClientSum, Sum, Rec) of
        error ->
            {stop, {down, out_of_sync}, State};
        duplicate ->
            error_logger:info_report([{resending, {IP, Port, Sum}}]),
            ok = resend(DNSSocket, IP, Port, Type, Buf, Rec),
            {next_state, proxy, State#state{sum_down = Sum},
                ?PROXY_TIMEOUT};
        Packet ->
%            error_logger:info_report([
%                {direction, down},
%                {dns_query, Rec}
%            ]),
            ok = inet:setopts(Socket, [{active, once}]),
            ok = gen_udp:send(DNSSocket, IP, Port, Packet),
            {next_state, proxy, State#state{
                sum_down = Sum + Size,
                data = [Rest],
                buf = Data}, ?PROXY_TIMEOUT}
    end;

proxy(timeout, State) ->
    {stop, timeout, State}.

%%--------------------------------------------------------------------
%%% Internal Functions
%%--------------------------------------------------------------------
seq(N) when is_integer(N) ->
    <<I1,I2,I3,I4>> = <<N:32>>,
    {I1,I2,I3,I4}.


%% Encode the data returned by the server as a DNS record
data(_, [<<>>]) ->
    {[],0,<<>>};
data(Type, Data) when is_list(Data) ->
    data(Type, list_to_binary(lists:reverse(Data)));

% TXT records
data(txt, <<D1:?MAXDATA/bytes, D2:?MAXDATA/bytes, Rest/binary>>) ->
    {[base64:encode_to_string(D1), base64:encode_to_string(D2)], 2*?MAXDATA, Rest};
data(txt, <<D1:?MAXDATA/bytes, Rest/binary>>) ->
    {[base64:encode_to_string(D1)], ?MAXDATA, Rest};
data(txt, Data) ->
    {[base64:encode_to_string(Data)], byte_size(Data), <<>>};

% NULL records
data(null, <<D1:(?MAXDATA*2)/bytes, Rest/binary>>) ->
    {base64:encode(D1), ?MAXDATA*2, Rest};
data(null, Data) ->
    {base64:encode(Data), byte_size(Data), <<>>};

% CNAME records
data(cname, <<D1:?MAXDATA/bytes, Rest/binary>>) ->
    {label(base32:encode(D1)), ?MAXDATA, Rest};
data(cname, Data) ->
    {label(base32:encode(Data)), byte_size(Data), <<>>}.


%% Each component (or label) of a CNAME can have a
%% max length of 63 bytes. A "." divides the labels.
label(String) when byte_size(String) < ?MAXLABEL ->
    String;
label(String) ->
    re:replace(String, ".{63}", "&.", [global, {return, list}]).


%% Packet sum checks
response(up, Sum, Sum, Rec) ->
    encode(seq(Sum), Rec);
response({down, Payload}, Sum, Sum, Rec) ->
    encode(Payload, Rec);
response(_, Sum1, Sum2, _) when Sum1 < Sum2 ->
    duplicate;
response(_, Sum1, Sum2, _) when Sum1 > Sum2 ->
    error.


%% Encode the DNS response to the client
encode(Data, #dns_rec{
        header = Header,
        qdlist = [#dns_query{
                domain = Domain,
                type = Type
            }|_]} = Rec) ->
    inet_dns:encode(Rec#dns_rec{
            header = Header#dns_header{
                qr = true,
                ra = true
            },
            anlist = [#dns_rr{
                    domain = Domain,
                    type = Type,
                    data = Data
                }]}).


% Resend a lost packet
resend(_Socket, _IP, _Port, _Type, [], _Rec) ->
    ok;
resend(Socket, IP, Port, Type, Data, Rec) ->
    {Payload, _, _} = data(Type, Data),
    gen_udp:send(Socket, IP, Port, encode(Payload, Rec)).


