%%%-------------------------------------------------------------------
%%% File    : p1_mysql_recv.erl
%%% Author  : Fredrik Thulin <ft@it.su.se>
%%% Descrip.: Handles data being received on a MySQL socket. Decodes
%%%           per-row framing and sends each row to parent.
%%%
%%% Created :  4 Aug 2005 by Fredrik Thulin <ft@it.su.se>
%%%
%%% Note    : All MySQL code was written by Magnus Ahltorp, originally
%%%           in the file p1_mysql.erl - I just moved it here.
%%%
%%% Copyright (c) 2001-2004 Kungliga Tekniska Högskolan
%%% See the file COPYING
%%%
%%%           Signals this receiver process can send to it's parent
%%%             (the parent is a p1_mysql_conn connection handler) :
%%%
%%%             {p1_mysql_recv, self(), data, Packet, Num}
%%%             {p1_mysql_recv, self(), closed, {error, Reason}}
%%%             {p1_mysql_recv, self(), closed, normal}
%%%
%%%           Internally (from inside init/4 to start_link/4) the
%%%           following signals may be sent to the parent process :
%%%
%%%             {p1_mysql_recv, self(), init, {ok, Sock}}
%%%             {p1_mysql_recv, self(), init, {error, E}}
%%%
%%%-------------------------------------------------------------------
-module(p1_mysql_recv).

%%--------------------------------------------------------------------
%% External exports (should only be used by the 'p1_mysql_conn' module)
%%--------------------------------------------------------------------
-export([start_link/5
	]).

-include_lib("kernel/include/inet.hrl").

-record(state, {
	  socket,
	  parent,
	  log_fun,
	  data
	 }).

-define(SECURE_CONNECTION, 32768).
-define(DNS_LOOKUP_TIMEOUT, 5000).

%%====================================================================
%% External functions
%%====================================================================

%%--------------------------------------------------------------------
%% Function: start_link(Host, Port, LogFun, Parent)
%%           Host = string()
%%           Port = integer()
%%           LogFun = undefined | function() of arity 3
%%           Parent = pid(), process that should get received frames
%% Descrip.: Start a process that connects to Host:Port and waits for
%%           data. When it has received a MySQL frame, it sends it to
%%           Parent and waits for the next frame.
%% Returns : {ok, RecvPid, Socket} |
%%           {error, Reason}
%%           RecvPid = pid(), receiver process pid
%%           Socket  = term(), gen_tcp socket
%%           Reason  = atom() | string()
%%--------------------------------------------------------------------
start_link(Host, Port, ConnectTimeout, LogFun, Parent) when is_list(Host),
							    is_integer(Port) ->
    RecvPid =
	spawn_link(fun () ->
			   init(Host, Port, LogFun, Parent)
		   end),
    %% wait for the socket from the spawned pid
    receive
	{p1_mysql_recv, RecvPid, init, {error, E}} ->
	    {error, E};
	{p1_mysql_recv, RecvPid, init, {ok, Socket}} ->
	    {ok, RecvPid, Socket}
    after ConnectTimeout ->
	    catch exit(RecvPid, kill),
	    {error, "timeout"}
    end.



%%====================================================================
%% Internal functions
%%====================================================================

%%--------------------------------------------------------------------
%% Function: init((Host, Port, LogFun, Parent)
%%           Host = string()
%%           Port = integer()
%%           LogFun = undefined | function() of arity 3
%%           Parent = pid(), process that should get received frames
%% Descrip.: Connect to Host:Port and then enter receive-loop.
%% Returns : error | never returns
%%--------------------------------------------------------------------
init(Host, Port, LogFun, Parent) ->
    case connect(Host, Port) of
	{ok, Sock} ->
	    Parent ! {p1_mysql_recv, self(), init, {ok, Sock}},
	    State = #state{socket  = Sock,
			   parent  = Parent,
			   log_fun = LogFun,
			   data    = <<>>
			  },
	    loop(State);
	{error, E} ->
	    Reason = format_inet_error(E),
	    p1_mysql:log(LogFun, error,
			 "p1_mysql_recv: Failed connecting to ~s:~p: ~s",
			 [Host, Port, Reason]),
	    Msg = lists:flatten(io_lib:format("connect failed: ~s", [Reason])),
	    Parent ! {p1_mysql_recv, self(), init, {error, Msg}}
    end.

%%--------------------------------------------------------------------
%% Function: loop(State)
%%           State = state record()
%% Descrip.: The main loop. Wait for data from our TCP socket and act
%%           on received data or signals that our socket was closed.
%% Returns : error | never returns
%%--------------------------------------------------------------------
loop(State) ->
    Sock = State#state.socket,
    receive
	{tcp, Sock, InData} ->
	    NewData = list_to_binary([State#state.data, InData]),
	    %% send data to parent if we have enough data
	    Rest = sendpacket(State#state.parent, NewData),
	    loop(State#state{data = Rest});
	{tcp_error, Sock, Reason} ->
	    p1_mysql:log(State#state.log_fun, error, "p1_mysql_recv: "
		      "Socket ~p closed : ~p", [Sock, Reason]),
	    State#state.parent ! {p1_mysql_recv, self(), closed,
				  {error, Reason}},
	    error;
	{tcp_closed, Sock} ->
	    p1_mysql:log(State#state.log_fun, debug, "p1_mysql_recv: "
		      "Socket ~p closed", [Sock]),
	    State#state.parent ! {p1_mysql_recv, self(), closed, normal},
	    error
    end.

%%--------------------------------------------------------------------
%% Function: sendpacket(Parent, Data)
%%           Parent = pid()
%%           Data   = binary()
%% Descrip.: Check if we have received one or more complete frames by
%%           now, and if so - send them to Parent.
%% Returns : Rest = binary()
%%--------------------------------------------------------------------
%% send data to parent if we have enough data
sendpacket(Parent, Data) ->
    case Data of
	<<Length:24/little, Num:8, D/binary>> ->
	    if
		Length =< size(D) ->
		    {Packet, Rest} = split_binary(D, Length),
		    Parent ! {p1_mysql_recv, self(), data, Packet, Num},
		    sendpacket(Parent, Rest);
		true ->
		    Data
	    end;
	_ ->
	    Data
    end.

%%--------------------------------------------------------------------
%% Connecting stuff
%%--------------------------------------------------------------------
connect(Host, Port) ->
    case lookup(Host) of
	{ok, AddrsFamilies} ->
	    do_connect(AddrsFamilies, Port, {error, nxdomain});
	{error, _} = Err ->
	    Err
    end.

do_connect([{IP, Family}|AddrsFamilies], Port, _Err) ->
    case gen_tcp:connect(IP, Port, [binary, {packet, 0}, Family]) of
	{ok, Sock} ->
	    {ok, Sock};
	{error, _} = Err ->
	    do_connect(AddrsFamilies, Port, Err)
    end;
do_connect([], _Port, Err) ->
    Err.

lookup(Host) ->
    case inet:parse_address(Host) of
	{ok, IP} ->
	    {ok, [{IP, get_addr_type(IP)}]};
	{error, _} ->
	    do_lookup([{Host, Family} || Family <- [inet6, inet]],
		      [], {error, nxdomain})
    end.

do_lookup([{Host, Family}|HostFamilies], AddrFamilies, Err) ->
    case inet:gethostbyname(Host, Family, ?DNS_LOOKUP_TIMEOUT) of
	{ok, HostEntry} ->
	    Addrs = host_entry_to_addrs(HostEntry),
	    AddrFamilies1 = [{Addr, Family} || Addr <- Addrs],
	    do_lookup(HostFamilies,
		      AddrFamilies ++ AddrFamilies1,
		      Err);
	{error, _} = Err1 ->
	    do_lookup(HostFamilies, AddrFamilies, Err1)
    end;
do_lookup([], [], Err) ->
    Err;
do_lookup([], AddrFamilies, _Err) ->
    {ok, AddrFamilies}.

host_entry_to_addrs(#hostent{h_addr_list = AddrList}) ->
    lists:filter(
      fun(Addr) ->
	      try get_addr_type(Addr) of
		  _ -> true
	      catch _:badarg ->
		      false
	      end
      end, AddrList).

get_addr_type({_, _, _, _}) -> inet;
get_addr_type({_, _, _, _, _, _, _, _}) -> inet6;
get_addr_type(_) -> erlang:error(badarg).

format_inet_error(closed) ->
    "connection closed";
format_inet_error(timeout) ->
    format_inet_error(etimedout);
format_inet_error(Reason) ->
    case inet:format_error(Reason) of
	"unknown POSIX error" -> atom_to_list(Reason);
	Txt -> Txt
    end.
