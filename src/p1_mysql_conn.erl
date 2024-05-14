%%%-------------------------------------------------------------------
%%% File    : p1_mysql_conn.erl
%%% Author  : Fredrik Thulin <ft@it.su.se>
%%% Descrip.: MySQL connection handler, handles de-framing of messages
%%%           received by the MySQL receiver process.
%%% Created :  5 Aug 2005 by Fredrik Thulin <ft@it.su.se>
%%% Modified: 11 Jan 2006 by Mickael Remond <mickael.remond@process-one.net>
%%%
%%% Note    : All MySQL code was written by Magnus Ahltorp, originally
%%%           in the file p1_mysql.erl - I just moved it here.
%%%
%%% Copyright (c) 2001-2004 Kungliga Tekniska Högskolan
%%% See the file COPYING
%%%
%%%
%%% This module handles a single connection to a single MySQL server.
%%% You can use it stand-alone, or through the 'p1_mysql' module if you
%%% want to have more than one connection to the server, or
%%% connections to different servers.
%%%
%%% To use it stand-alone, set up the connection with
%%%
%%%   {ok, Pid} = p1_mysql_conn:start(Host, Port, User, Password,
%%%                                Database, LogFun)
%%%
%%%         Host     = string()
%%%         Port     = integer()
%%%         User     = string()
%%%         Password = string()
%%%         Database = string()
%%%         LogFun   = undefined | (gives logging to console)
%%%                    function() of arity 3 (Level, Fmt, Args)
%%%
%%% Note: In stand-alone mode you have to start Erlang crypto application by
%%% yourself with crypto:start()
%%%
%%% and then make MySQL querys with
%%%
%%%   Result = p1_mysql_conn:fetch(Pid, Query, self())
%%%
%%%         Result = {data, MySQLRes}    |
%%%                  {updated, MySQLRes} |
%%%                  {error, MySQLRes}
%%%          Where: MySQLRes = #p1_mysql_result
%%%
%%% Actual data can be extracted from MySQLRes by calling the following API
%%% functions:
%%%     - on data received:
%%%          FieldInfo = p1_mysql:get_result_field_info(MysqlRes)
%%%          AllRows   = p1_mysql:get_result_rows(MysqlRes)
%%%         with FieldInfo = list() of {Table, Field, Length, Name}
%%%          and AllRows = list() of list() representing records
%%%     - on update:
%%%          Affected= p1_mysql:get_result_affected_rows(MysqlRes)
%%%         with Affected = integer()
%%%     - on error:
%%%          Reason    = p1_mysql:get_result_reason(MysqlRes)
%%%         with Reason = string()
%%%-------------------------------------------------------------------

-module(p1_mysql_conn).
-behavior(gen_server).

-define(CONNECT_TIMEOUT, 5000).

%%--------------------------------------------------------------------
%% External exports
%%--------------------------------------------------------------------
-export([start/6,
	 start/7,
	 start/8,
	 start_link/6,
	 start_link/7,
	 start_link/8,
	 fetch/3,
	 fetch/4,
	 squery/4,
	 prepared_query/7,
	 stop/1,
	 init/1,
	 handle_call/3,
	 handle_cast/2, terminate/2, code_change/3, handle_info/2]).

%%--------------------------------------------------------------------
%% External exports (should only be used by the 'p1_mysql_auth' module)
%%--------------------------------------------------------------------
-export([do_recv/3, do_send/4, get_field_datatype/1]).

-include("p1_mysql.hrl").
-include("p1_mysql_consts.hrl").
-include("p1_mysql_state.hrl").
-include_lib("kernel/include/inet.hrl").

-define(SECURE_CONNECTION, 32768).
-define(MYSQL_QUERY_OP, 3).
-define(DEFAULT_STANDALONE_TIMEOUT, 5000).
-define(DEFAULT_RESULT_TYPE, list).
-define(MYSQL_4_0, 40). %% Support for MySQL 4.0.x
-define(MYSQL_4_1, 41). %% Support for MySQL 4.1.x et 5.0.x

%%====================================================================
%% External functions
%%====================================================================

%%--------------------------------------------------------------------
%% Function: start(Host, Port, User, Password, Database, LogFun)
%% Function: start_link(Host, Port, User, Password, Database, LogFun)
%%           Host     = string()
%%           Port     = integer()
%%           User     = string()
%%           Password = string()
%%           Database = string()
%%           LogFun   = undefined | function() of arity 3
%% Descrip.: Starts a p1_mysql_conn process that connects to a MySQL
%%           server, logs in and chooses a database.
%% Returns : {ok, Pid} | {error, Reason}
%%           Pid    = pid()
%%           Reason = string()
%%--------------------------------------------------------------------
start(Host, Port, User, Password, Database, LogFun) ->
    start(Host, Port, User, Password, Database, ?CONNECT_TIMEOUT, LogFun).

start(Host, Port, User, Password, Database, ConnectTimeout,
      LogFun) ->
    start(Host, Port, User, Password, Database, ConnectTimeout, LogFun, []).

start(Host, Port, User, Password, Database, ConnectTimeout,
      LogFun, SSLOpts) when is_list(Host),
			    is_integer(Port),
			    is_list(User),
			    is_list(Password),
			    is_list(Database) ->
    gen_server:start(?MODULE, [Host, Port, User, Password, Database,
			       ConnectTimeout, LogFun, SSLOpts],
		     [{timeout, ConnectTimeout}]).

start_link(Host, Port, User, Password, Database, LogFun) ->
    start_link(Host, Port, User, Password, Database, ?CONNECT_TIMEOUT, LogFun).

start_link(Host, Port, User, Password, Database, ConnectTimeout,
	   LogFun) ->
    start_link(Host, Port, User, Password, Database, ConnectTimeout,
	       LogFun, []).

start_link(Host, Port, User, Password, Database, ConnectTimeout,
	   LogFun, SSLOpts) when is_list(Host),
				 is_integer(Port),
				 is_list(User),
				 is_list(Password),
				 is_list(Database) ->
    gen_server:start_link(?MODULE, [Host, Port, User, Password, Database,
				    ConnectTimeout, LogFun, SSLOpts],
			  [{timeout, ConnectTimeout}]).

%%--------------------------------------------------------------------
%% Function: fetch(Pid, Query, From)
%%           fetch(Pid, Query, From, Timeout)
%%           Pid     = pid(), p1_mysql_conn to send fetch-request to
%%           Query   = string(), MySQL query in verbatim
%%           From    = pid() or term(), use a From of self() when
%%                     using this module for a single connection,
%%                     or pass the gen_server:call/3 From argument if
%%                     using a gen_server to do the querys (e.g. the
%%                     mysql_dispatcher)
%%           Timeout = integer() | infinity, gen_server timeout value
%% Descrip.: Send a query and wait for the result if running stand-
%%           alone (From = self()), but don't block the caller if we
%%           are not running stand-alone (From = gen_server From).
%% Returns : ok                        | (non-stand-alone mode)
%%           {data, #p1_mysql_result}     | (stand-alone mode)
%%           {updated, #p1_mysql_result}  | (stand-alone mode)
%%           {error, #p1_mysql_result}      (stand-alone mode)
%%           FieldInfo = term()
%%           Rows      = list() of [string()]
%%           Reason    = term()
%%--------------------------------------------------------------------

fetch(Pid, Query, From) ->
    squery(Pid, Query, From, []).
fetch(Pid, Query, From, Timeout) ->
    squery(Pid, Query, From, [{timeout, Timeout}]).

squery(Pid, Query, From, Options) when is_pid(Pid),
				       (is_list(Query) or is_binary(Query)) ->
    Self = self(),
    Timeout = get_option(timeout, Options, ?DEFAULT_STANDALONE_TIMEOUT),
    TRef = erlang:make_ref(),
    Pid ! {fetch, TRef, Query, From, Options},
    case From of
	Self ->
	    %% We are not using a mysql_dispatcher, await the response
	    wait_fetch_result(TRef, Pid, Timeout);
	_ ->
	    %% From is gen_server From, Pid will do gen_server:reply()
	    %% when it has an answer
	    ok
    end.

prepared_query(Pid, Query, QueryId, Args, Types, From, Options) when is_pid(Pid),
						     (is_list(Query) or is_binary(Query) or is_function(Query)),
						     is_list(Args), is_list(Types) ->
    Self = self(),
    Timeout = get_option(timeout, Options, ?DEFAULT_STANDALONE_TIMEOUT),
    TRef = erlang:make_ref(),
    Pid ! {prepared_query, TRef, Query, QueryId, Args, Types, From, Options},
    case From of
	Self ->
	    %% We are not using a mysql_dispatcher, await the response
	    wait_fetch_result(TRef, Pid, Timeout);
	_ ->
	    %% From is gen_server From, Pid will do gen_server:reply()
	    %% when it has an answer
	    ok
    end.

wait_fetch_result(TRef, Pid, Timeout) ->
    receive
	{'EXIT', Pid, _Reason} ->
	    {error, #p1_mysql_result{error = "connection closed"}};
	{fetch_result, TRef, Pid, Result} ->
	    Result;
	{fetch_result, _BadRef, Pid, _Result} ->
	    wait_fetch_result(TRef, Pid, Timeout)
    after Timeout ->
	stop(Pid),
	timer:kill_after(?DEFAULT_STANDALONE_TIMEOUT, Pid),
	{error, #p1_mysql_result{error = "query timed out"}}
    end.

stop(Pid) ->
    Pid ! close.


%%--------------------------------------------------------------------
%% Function: do_recv(LogFun, RecvPid, SeqNum)
%%           LogFun  = undefined | function() with arity 3
%%           RecvPid = pid(), p1_mysql_recv process
%%           SeqNum  = undefined | integer()
%% Descrip.: Wait for a frame decoded and sent to us by RecvPid.
%%           Either wait for a specific frame if SeqNum is an integer,
%%           or just any frame if SeqNum is undefined.
%% Returns : {ok, Packet, Num} |
%%           {error, Reason}
%%           Reason = term()
%%
%% Note    : Only to be used externally by the 'p1_mysql_auth' module.
%%--------------------------------------------------------------------
do_recv(LogFun, #state{data = Last} = State, SeqNum) when Last /= <<>> ->
    case extract_packet(Last) of
	{Packet, Num, Rest} ->
	    {ok, Packet, Num, State#state{data = Rest}};
	_ ->
	    do_recv2(LogFun, State, SeqNum)
    end;
do_recv(LogFun, State, SeqNum) ->
    do_recv2(LogFun, State, SeqNum).

do_recv2(LogFun, #state{socket = {_SockMod, Socket}, data = Last} = State, SeqNum) when is_function(LogFun);
											LogFun == undefined ->
    receive
	close ->
	    %ejabberd_sql:sql_query(<<"localhost">>, <<"select 1+1;">>).
	    p1_mysql:log(LogFun, error, "p1_mysql_conn:"
					" received close~n", []),
	    {error, "p1_mysql_recv: socket was closed"};
	{T, Socket, Data} when T == tcp; T == ssl ->
	    NewData = <<Last/binary, Data/binary>>,
	    case extract_packet(NewData) of
		{Packet, Num, Rest} ->
		    {ok, Packet, Num, State#state{data = Rest}};
		Rest ->
		    do_recv(LogFun, State#state{data = Rest}, SeqNum)
	    end;
	{T, Socket, Reason} when T == tcp_error; T == ssl_error ->
	    p1_mysql:log(LogFun, error, "p1_mysql_conn: "
					"Socket ~p closed : ~p", [Socket, Reason]),
	    {error, "p1_mysql_recv: socket was closed"};
	{T, Socket} when T == tcp_closed; T == ssl_closed ->
	    p1_mysql:log(LogFun, error, "p1_mysql_conn: "
					"Socket ~p closed", [Socket]),
	    {error, "p1_mysql_recv: socket was closed"};
	Other when not is_tuple(Other) orelse size(Other) /= 3 orelse element(1, Other) /= system ->
	    p1_mysql:log(LogFun, error, "p1_mysql_conn: Unknown message ~p~n", [Other]),
	    {error, "p1_mysql_recv: socket was closed"}
    end.

extract_packet(Data) ->
    case Data of
	<<Length:24/little, Num:8, D/binary>> ->
	    if
		Length =< size(D) ->
		    {Packet, Rest} = split_binary(D, Length),
		    {Packet, Num, Rest};
		true ->
		    Data
	    end;
	_ ->
	    Data
    end.

%%====================================================================
%% Internal functions
%%====================================================================

%%--------------------------------------------------------------------
%% Function: init(Host, Port, User, Password, Database, LogFun,
%%                Parent)
%%           Host     = string()
%%           Port     = integer()
%%           User     = string()
%%           Password = string()
%%           Database = string()
%%           LogFun   = undefined | function() of arity 3
%%           Parent   = pid() of process starting this p1_mysql_conn
%% Descrip.: Connect to a MySQL server, log in and chooses a database.
%%           Report result of this to Parent, and then enter loop() if
%%           we were successfull.
%% Returns : void() | does not return
%%--------------------------------------------------------------------
init([Host, Port, User, Password, Database, ConnectTimeout, LogFun, SSLOpts]) ->
    case connect(Host, Port, LogFun, ConnectTimeout) of
	{ok, Sock0} ->
	    State = #state{socket = {gen_tcp, Sock0},
			   log_fun = LogFun,
			   data = <<>>},
	    case mysql_init(State, User, Password, LogFun, SSLOpts) of
		{ok, NState} ->
		    case do_query(NState, "use " ++ Database, [{result_type, binary}]) of
			{error, MySQLRes} ->
			    p1_mysql:log(LogFun, error,
					 "p1_mysql_conn: Failed changing"
					 " to database ~p : ~p",
					 [Database,
					  p1_mysql:get_result_reason(MySQLRes)]),
			    {SockMod, RawSock} = NState#state.socket,
			    SockMod:close(RawSock),
			    {stop, normal};
			%% ResultType: data | updated
			{_ResultType, _MySQLRes, NState2} ->
			    {ok, NState2}
		    end;
		{error, _Reason} ->
		    {stop, normal}
	    end;
	E ->
	    p1_mysql:log(LogFun, error, "p1_mysql_conn: "
					"Failed connecting to ~p:~p : ~p",
			 [Host, Port, E]),
	    {stop, normal}
    end.

handle_call(_Request, _From, #state{log_fun = LogFun} = State) ->
    p1_mysql:log(LogFun, error, "Unhandled call ~p",
		 [_Request]),
    {reply, {error, badarg}, State}.

handle_cast(_Request, #state{log_fun = LogFun} = State) ->
    p1_mysql:log(LogFun, error, "Unhandled cast ~p",
		 [_Request]),
    {noreply, State}.

handle_info({fetch, Ref, Query, GenSrvFrom, Options}, State) ->
    %% GenSrvFrom is either a gen_server:call/3 From term(),
    %% or a pid if no gen_server was used to make the query
    {NState, Res} =
    case do_query(State, Query, Options) of
	{error, R} -> {State, {error, R}};
	{T, R, S} -> {S, {T, R}}
    end,
    case is_pid(GenSrvFrom) of
	true ->
	    %% The query was not sent using gen_server mechanisms
	    GenSrvFrom ! {fetch_result, Ref, self(), Res};
	false ->
	    %% the timer is canceled in wait_fetch_result/2, but we wait on that funtion only if the query
	    %% was not sent using the mysql gen_server. So we at least should try to cancel the timer here
	    %% (no warranty, the gen_server can still receive timeout messages)
	    erlang:cancel_timer(Ref),
	    gen_server:reply(GenSrvFrom, Res)
    end,
    case Res of
	{error, #p1_mysql_result{error = "p1_mysql_recv: socket was closed"}} ->
	    p1_mysql:log(State#state.log_fun, error, "p1_mysql_conn: "
						     "Connection closed, exiting.", []),
	    {stop, normal, State};
	_ ->
	    {noreply, NState}
    end;
handle_info({prepared_query, Ref, Query, QueryId, Args, Types, GenSrvFrom, Options}, State) ->
    {NState, Res} = p1_mysql_bin:prepare_and_execute(State, Query, QueryId, Args, Types, Options),
    case is_pid(GenSrvFrom) of
	true ->
	    %% The query was not sent using gen_server mechanisms
	    GenSrvFrom ! {fetch_result, Ref, self(), Res};
	false ->
	    %% the timer is canceled in wait_fetch_result/2, but we wait on that funtion only if the query
	    %% was not sent using the mysql gen_server. So we at least should try to cancel the timer here
	    %% (no warranty, the gen_server can still receive timeout messages)
	    erlang:cancel_timer(Ref),
	    gen_server:reply(GenSrvFrom, Res)
    end,
    case Res of
	{error, #p1_mysql_result{error = "p1_mysql_recv: socket was closed"}} ->
	    p1_mysql:log(State#state.log_fun, error, "p1_mysql_conn: "
						     "Connection closed, exiting.", []),
	    {stop, normal, NState};
	_ ->
	    {noreply, NState}
    end;
handle_info({T, _Socket, Data}, #state{data = Last} = State) when T == tcp; T == ssl ->
    NewData = <<Last/binary, Data/binary>>,
    {noreply, State#state{data = NewData}};
handle_info({T, Socket, Reason}, #state{log_fun = LogFun} = State) when T == tcp_error; T == ssl_error ->
    p1_mysql:log(LogFun, error, "p1_mysql_conn: "
				"Socket ~p closed : ~p", [Socket, Reason]),
    {stop, normal, State};
handle_info({T, Socket}, #state{log_fun = LogFun} = State) when T == tcp_closed; T == ssl_closed ->
    p1_mysql:log(LogFun, error, "p1_mysql_conn: "
				"Socket ~p closed", [Socket]),
    {stop, normal, State};
handle_info(close, State) ->
    p1_mysql:log(State#state.log_fun, info, "p1_mysql_conn: "
					    "Received close signal, exiting.", []),
    {stop, normal, State};
handle_info(Unknown, State) ->
    p1_mysql:log(State#state.log_fun, error, "p1_mysql_conn: "
					     "Received unknown signal, exiting : ~p",
		 [Unknown]),
    {stop, normal, State}.

terminate(_Reason, State) ->
    {SockMod, Socket} = State#state.socket,
    Result = SockMod:close(Socket),
    p1_mysql:log(State#state.log_fun, normal, "Closing connection ~p: ~p~n",
		 [State#state.socket, Result]),
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%--------------------------------------------------------------------
%% Function: mysql_init(Sock, RecvPid, User, Password, LogFun)
%%           Sock     = term(), gen_tcp socket
%%           RecvPid  = pid(), p1_mysql_recv process
%%           User     = string()
%%           Password = string()
%%           LogFun   = undefined | function() with arity 3
%% Descrip.: Try to authenticate on our new socket.
%% Returns : {ok, SockPair, Version} | {error, Reason}
%%           Reason = string()
%%--------------------------------------------------------------------
mysql_init(State, User, Password, LogFun, SSLOpts) ->
    case do_recv(LogFun, State, undefined) of
	{ok, Packet, InitSeqNum, NState} ->
	    case greeting(Packet, LogFun) of
		{ok, {Version, Salt, Caps, AuthPlug}} ->
		    case Caps band ?CLIENT_SSL of
			0 ->
			    case proplists:get_bool(ssl_required, SSLOpts) of
				true ->
				    p1_mysql:log(LogFun, error, "p1_mysql_conn: "
								"init failed - ssl required, but not available~n",
						 []),
				    {error, "SSL not available"};
				false ->
				    authenticate(NState, User, Password, LogFun,
						 InitSeqNum, Version, Salt, Caps, AuthPlug)
			    end;
			_ ->
			    case proplists:get_bool(ssl, SSLOpts) orelse proplists:get_bool(ssl_required, SSLOpts) of
				true ->
				    case start_ssl(NState, SSLOpts, LogFun, InitSeqNum + 1, AuthPlug) of
					{ok, NewState} ->
					    authenticate(NewState, User, Password, LogFun,
							 InitSeqNum + 1, Version, Salt, Caps, AuthPlug);
					{error, Reason} ->
					    {error, Reason}
				    end;
				_ ->
				    authenticate(NState, User, Password, LogFun,
						 InitSeqNum, Version, Salt, Caps, AuthPlug)
			    end
		    end;
		{error, Reason} -> {error, Reason}
	    end;
	{error, Reason} ->
	    {error, Reason}
    end.

%% part of mysql_init/4

start_ssl(#state{socket = {_, Sock}} = State, SSLOpts, LogFun, SeqNum, AuthPlug) ->
    Packet = p1_mysql_auth:get_auth_head(AuthPlug, ?CLIENT_SSL),
    Data = <<(size(Packet)):24/little, SeqNum:8, Packet/binary>>,
    p1_mysql:log(LogFun, debug, "p1_mysql_conn send start ssl ~p: ~p", [SeqNum, Packet]),
    gen_tcp:send(Sock, Data),
    {[A, B, C], _} = proplists:split(SSLOpts, [certfile, cacertfile, verify]),
    Filtered = A ++ B ++ C,
    case ssl:connect(Sock, [binary, {packet, 0} | Filtered]) of
	{ok, SSLSock} ->
	    {ok, State#state{socket = {ssl, SSLSock}}};
	{error, Reason} ->
	    p1_mysql:log(LogFun, error, "p1_mysql_conn: "
					"ssl start failed: ~p~n",
			 [Reason]),
	    {error, "ssl failed"}
    end.

authenticate(State, User, Password, LogFun, SeqNum,
	     Version, Salt, Caps, AuthPlug) ->
    AuthRes = p1_mysql_auth:do_auth(AuthPlug, State,
				    SeqNum + 1,
				    User, Password,
				    Salt, Caps, LogFun),
    case AuthRes of
	{ok, <<0:8, _Rest/binary>>, _RecvNum, NState} ->
	    {ok, NState#state{mysql_version = Version}};
	{ok, <<255:8, Code:16/little, Message/binary>>, _RecvNum, _NState} ->
	    p1_mysql:log(LogFun, error, "p1_mysql_conn: "
					"init error ~p: ~p~n",
			 [Code, binary_to_list(Message)]),
	    {error, binary_to_list(Message)};
	{ok, RecvPacket, _RecvNum, _NState} ->
	    p1_mysql:log(LogFun, error, "p1_mysql_conn: "
					"init unknown error ~p~n",
			 [binary_to_list(RecvPacket)]),
	    {error, binary_to_list(RecvPacket)};
	{error, Reason} ->
	    p1_mysql:log(LogFun, error, "p1_mysql_conn: "
					"init failed receiving data : ~p~n",
			 [Reason]),
	    {error, Reason}
    end.

greeting(Packet, LogFun) ->
    <<Protocol:8, Rest/binary>> = Packet,
    case Protocol of
	9 ->
	    {ServerStatusStr, Rest2} = asciz(Rest),
	    <<_TreadID:32/little, Rest3/binary>> = Rest2,
	    {Salt, _} = asciz(Rest3),
	    p1_mysql:log(LogFun, debug, "p1_mysql_conn: greeting version ~p (protocol ~p) "
					"salt ~p",
			 [ServerStatusStr, Protocol, Salt]),
	    {ok, {?MYSQL_4_0, Salt, 0, "old_pass"}};
	10 ->
	    {ServerStatusStr, Rest2} = asciz(Rest),
	    <<_TreadID:32/little, Salt1:8/binary, _:8, Caps1:16/little,
	      CharSet:8, _StatusFlags:16/little, Caps2:16/little,
	      AuthPlugLen:8, _:10/binary, Rest3/binary>> = Rest2,
	    Caps = (Caps2 bsl 16) bor Caps1,
	    {Salt2, AuthPlug} = case {Caps band ?CLIENT_PLUGIN_AUTH, AuthPlugLen} of
				    {0, 0} ->
					Len = max(13, AuthPlugLen - 8) - 1,
					<<S:Len/binary, _/binary>> = Rest3,
					{S, "mysql_native_password"};
				    {?CLIENT_PLUGIN_AUTH, _} ->
					Len = max(13, AuthPlugLen - 8) - 1,
					<<S:Len/binary, _:8, Rest4/binary>> = Rest3,
					{AuthPlugName, _} = asciz(Rest4),
					{S, AuthPlugName}
				end,
	    Salt = binary_to_list(<<Salt1/binary, Salt2/binary>>),
	    p1_mysql:log(LogFun, debug, "p1_mysql_conn: greeting version ~p (protocol ~p) "
					"salt ~p caps ~p serverchar ~p auth_plug: ~p",
			 [ServerStatusStr, Protocol, Salt, Caps, CharSet, AuthPlug]),
	    {ok, {?MYSQL_4_1, Salt, Caps, AuthPlug}};
	255 ->
	    case Rest of
		<<Code:16/little>> ->
		    {error, io_lib:format("p1_mysql_conn: greetings error code ~p", [Code])};
		<<_Code:16/little, Msg/binary>> ->
		    {error, io_lib:format("p1_mysql_conn: greetings error: ~s", [Msg])};
		_ -> {error, "p1_mysql_conn: greetings error"}
	    end
    end.

%% part of greeting/2
asciz(Data) ->
    p1_mysql:asciz_binary(Data, []).

%%--------------------------------------------------------------------
%% Function: get_query_response(LogFun, RecvPid)
%%           LogFun  = undefined | function() with arity 3
%%           RecvPid = pid(), p1_mysql_recv process
%%           Version = integer(), Representing MySQL version used
%% Descrip.: Wait for frames until we have a complete query response.
%% Returns :   {data, #p1_mysql_result}
%%             {updated, #p1_mysql_result}
%%             {error, #p1_mysql_result}
%%           FieldInfo    = list() of term()
%%           Rows         = list() of [string()]
%%           AffectedRows = int()
%%           Reason       = term()
%%--------------------------------------------------------------------
get_query_response(LogFun, State, Version, Options) ->
    case do_recv(LogFun, State, undefined) of
	{ok, <<Fieldcount:8, Rest/binary>>, _, NState} ->
	    case Fieldcount of
		0 ->
		    %% No Tabular data
		    AffectedRows = case Rest of
				       <<16#fc, Value:16/little, _/binary>> -> Value;
				       <<16#fd, Value:24/little, _/binary>> -> Value;
				       <<16#fe, Value:64/little, _/binary>> -> Value;
				       <<Value:8, _/binary>> -> Value
				   end,
		    {updated, #p1_mysql_result{affectedrows = AffectedRows}, NState};
		255 ->
		    <<_Code:16/little, Message/binary>> = Rest,
		    {error, #p1_mysql_result{error = binary_to_list(Message)}};
		_ ->
		    %% Tabular data received
		    ResultType = get_option(result_type, Options, ?DEFAULT_RESULT_TYPE),
		    case get_fields(LogFun, NState, [], Version, ResultType) of
			{ok, Fields, NState2} ->
			    case get_rows(Fieldcount, LogFun, NState2, ResultType, []) of
				{ok, Rows, NState3} ->
				    {data, #p1_mysql_result{fieldinfo = Fields,
							    rows = Rows}, NState3};
				{error, Reason} ->
				    {error, #p1_mysql_result{error = Reason}}
			    end;
			{error, Reason} ->
			    {error, #p1_mysql_result{error = Reason}}
		    end
	    end;
	{error, Reason} ->
	    {error, #p1_mysql_result{error = Reason}}
    end.

%%--------------------------------------------------------------------
%% Function: get_fields(LogFun, RecvPid, [], Version)
%%           LogFun  = undefined | function() with arity 3
%%           RecvPid = pid(), p1_mysql_recv process
%%           Version = integer(), Representing MySQL version used
%% Descrip.: Received and decode field information.
%% Returns : {ok, FieldInfo} |
%%           {error, Reason}
%%           FieldInfo = list() of term()
%%           Reason    = term()
%%--------------------------------------------------------------------
%% Support for MySQL 4.0.x:
get_fields(LogFun, State, Res, ?MYSQL_4_0, ResultType) ->
    case do_recv(LogFun, State, undefined) of
	{ok, Packet, _Num, NState} ->
	    case Packet of
		<<254:8>> ->
		    {ok, lists:reverse(Res), NState};
		<<254:8, Rest/binary>> when size(Rest) < 8 ->
		    {ok, lists:reverse(Res), NState};
		_ ->
		    {Table, Rest} = get_with_length(Packet),
		    {Field, Rest2} = get_with_length(Rest),
		    {LengthB, Rest3} = get_with_length(Rest2),
		    LengthL = size(LengthB)*8,
		    <<Length:LengthL/little>> = LengthB,
		    {Type, Rest4} = get_with_length(Rest3),
		    {_Flags, _Rest5} = get_with_length(Rest4),
		    if ResultType == list ->
			This = {binary_to_list(Table),
				binary_to_list(Field),
				Length,
				%% TODO: Check on MySQL 4.0 if types are specified
				%%       using the same 4.1 formalism and could
				%%       be expanded to atoms:
				binary_to_list(Type)};
			ResultType == binary ->
			    This = {Table, Field, Length, Type}
		    end,
		    get_fields(LogFun, NState, [This | Res],
			       ?MYSQL_4_0, ResultType)
	    end;
	{error, Reason} ->
	    {error, Reason}
    end;
%% Support for MySQL 4.1.x and 5.x:
get_fields(LogFun, State, Res, ?MYSQL_4_1, ResultType) ->
    case do_recv(LogFun, State, undefined) of
	{ok, Packet, _Num, NState} ->
	    case Packet of
		<<254:8>> ->
		    {ok, lists:reverse(Res), NState};
		<<254:8, Rest/binary>> when size(Rest) < 8 ->
		    {ok, lists:reverse(Res), NState};
		_ ->
		    {_Catalog, Rest} = get_with_length(Packet),
		    {_Database, Rest2} = get_with_length(Rest),
		    {Table, Rest3} = get_with_length(Rest2),
		    %% OrgTable is the real table name if Table is an alias
		    {_OrgTable, Rest4} = get_with_length(Rest3),
		    {Field, Rest5} = get_with_length(Rest4),
		    %% OrgField is the real field name if Field is an alias
		    {_OrgField, Rest6} = get_with_length(Rest5),

		    <<_Metadata:8/little, _Charset:16/little,
		      Length:32/little, Type:8/little,
		      _Flags:16/little, _Decimals:8/little,
		      _Rest7/binary>> = Rest6,
		    if ResultType == list ->
			This = {binary_to_list(Table),
				binary_to_list(Field),
				Length,
				get_field_datatype(Type)};
			ResultType == binary ->
			    This = {Table, Field, Length,
				    get_field_datatype(Type)}
		    end,
		    get_fields(LogFun, NState, [This | Res],
			       ?MYSQL_4_1, ResultType)
	    end;
	{error, Reason} ->
	    {error, Reason}
    end.

%%--------------------------------------------------------------------
%% Function: get_rows(N, LogFun, RecvPid, [])
%%           N       = integer(), number of rows to get
%%           LogFun  = undefined | function() with arity 3
%%           RecvPid = pid(), p1_mysql_recv process
%% Descrip.: Receive and decode a number of rows.
%% Returns : {ok, Rows} |
%%           {error, Reason}
%%           Rows = list() of [string()]
%%--------------------------------------------------------------------
get_rows(N, LogFun, State, ResultType, Res) ->
    case do_recv(LogFun, State, undefined) of
	{ok, Packet, _Num, NState} ->
	    case Packet of
		<<254:8, Rest/binary>> when size(Rest) < 8 ->
		    {ok, lists:reverse(Res), NState};
		_ ->
		    {ok, This} = get_row(N, Packet, ResultType, []),
		    get_rows(N, LogFun, NState, ResultType, [This | Res])
	    end;
	{error, Reason} ->
	    {error, Reason}
    end.


%% part of get_rows/4
get_row(0, _Data, _ResultType, Res) ->
    {ok, lists:reverse(Res)};
get_row(N, Data, ResultType, Res) ->
    {Col, Rest} = get_with_length(Data),
    This = case Col of
	       null ->
		   null;
	       _ ->
		   if
		       ResultType == list ->
			   binary_to_list(Col);
		       ResultType == binary ->
			   Col
		   end
	   end,
    get_row(N - 1, Rest, ResultType, [This | Res]).

get_with_length(<<251:8, Rest/binary>>) ->
    {null, Rest};
get_with_length(<<252:8, Length:16/little, Rest/binary>>) ->
    split_binary(Rest, Length);
get_with_length(<<253:8, Length:24/little, Rest/binary>>) ->
    split_binary(Rest, Length);
get_with_length(<<254:8, Length:64/little, Rest/binary>>) ->
    split_binary(Rest, Length);
get_with_length(<<Length:8, Rest/binary>>) when Length < 251 ->
    split_binary(Rest, Length).

%%--------------------------------------------------------------------
%% Function: do_query(State, Query)
%%           do_query(Sock, RecvPid, LogFun, Query)
%%           Sock    = term(), gen_tcp socket
%%           RecvPid = pid(), p1_mysql_recv process
%%           LogFun  = undefined | function() with arity 3
%%           Query   = string()
%% Descrip.: Send a MySQL query and block awaiting it's response.
%% Returns : result of get_query_response/2 | {error, Reason}
%%--------------------------------------------------------------------
do_query(#state{socket = Sock, log_fun = LogFun, mysql_version = Version} = State,
	 Query, Options) when (is_list(Query) or is_binary(Query)) ->
    Packet = list_to_binary([?MYSQL_QUERY_OP, Query]),
    case do_send(Sock, Packet, 0, LogFun) of
	ok ->
	    get_query_response(LogFun, State, Version, Options);
	{error, Reason} ->
	    Msg = io_lib:format("Failed sending data on socket : ~p", [Reason]),
	    {error, Msg}
    end.

%%--------------------------------------------------------------------
%% Function: do_send(Sock, Packet, SeqNum, LogFun)
%%           Sock   = {SockMod, Socket}, socket
%%           Packet = binary()
%%           SeqNum = integer(), packet sequence number
%%           LogFun = undefined | function() with arity 3
%% Descrip.: Send a packet to the MySQL server.
%% Returns : result of gen_tcp:send/2
%%--------------------------------------------------------------------
do_send({SockMod, Sock}, Packet, SeqNum, _LogFun) when is_binary(Packet),
						       is_integer(SeqNum) ->
    Data = <<(size(Packet)):24/little, SeqNum:8, Packet/binary>>,
    %p1_mysql:log(_LogFun, debug, "p1_mysql_conn: send packet ~p: ~p",
    %[SeqNum, Data]),
    SockMod:send(Sock, Data).

%%--------------------------------------------------------------------
%% Function: get_field_datatype(DataType)
%%           DataType = integer(), MySQL datatype
%% Descrip.: Return MySQL field datatype as description string
%% Returns : String, MySQL datatype
%%--------------------------------------------------------------------
get_field_datatype(0) -> 'DECIMAL';
get_field_datatype(1) -> 'TINY';
get_field_datatype(2) -> 'SHORT';
get_field_datatype(3) -> 'LONG';
get_field_datatype(4) -> 'FLOAT';
get_field_datatype(5) -> 'DOUBLE';
get_field_datatype(6) -> 'NULL';
get_field_datatype(7) -> 'TIMESTAMP';
get_field_datatype(8) -> 'LONGLONG';
get_field_datatype(9) -> 'INT24';
get_field_datatype(10) -> 'DATE';
get_field_datatype(11) -> 'TIME';
get_field_datatype(12) -> 'DATETIME';
get_field_datatype(13) -> 'YEAR';
get_field_datatype(14) -> 'NEWDATE';
get_field_datatype(16) -> 'BIT';
get_field_datatype(246) -> 'DECIMAL';
get_field_datatype(247) -> 'ENUM';
get_field_datatype(248) -> 'SET';
get_field_datatype(249) -> 'TINYBLOB';
get_field_datatype(250) -> 'MEDIUM_BLOG';
get_field_datatype(251) -> 'LONG_BLOG';
get_field_datatype(252) -> 'BLOB';
get_field_datatype(253) -> 'VAR_STRING';
get_field_datatype(254) -> 'STRING';
get_field_datatype(255) -> 'GEOMETRY'.

%%--------------------------------------------------------------------
%% Function: get_option(Key1, Options, Default) -> Value1
%%           Options = [Option]
%%           Option = {Key2, Value2}
%%           Key1 = Key2 = atom()
%%           Value1 = Value2 = Default = term()
%% Descrip.: Return the option associated with Key passed to squery/4
%%--------------------------------------------------------------------

get_option(Key, Options, Default) ->
    case lists:keysearch(Key, 1, Options) of
	{value, {_, Value}} ->
	    Value;
	false ->
	    Default
    end.

%%--------------------------------------------------------------------
%% Connecting stuff
%%--------------------------------------------------------------------
connect(Host, Port, LogFun, Timeout) ->
    case lookup(Host, Timeout) of
	{ok, AddrsFamilies} ->
	    do_connect(AddrsFamilies, Port, {error, nxdomain}, Timeout);
	{error, E} ->
	    Reason = inet:format_error(E),
	    p1_mysql:log(LogFun, error,
			 "p1_mysql_conn: Failed connecting to ~s:~p: ~s",
			 [Host, Port, Reason]),
	    Msg = lists:flatten(io_lib:format("connect failed: ~s", [Reason])),
	    {error, Msg}
    end.

do_connect([{IP, Family} | AddrsFamilies], Port1, _Err, Timeout) ->
    Port = case Family of
        local -> 0;
        _ -> Port1
    end,
    case gen_tcp:connect(IP, Port, [binary, {packet, 0}, {active, true}, Family], Timeout) of
	{ok, Sock} ->
	    {ok, Sock};
	{error, _} = Err ->
	    do_connect(AddrsFamilies, Port, Err, Timeout)
    end;
do_connect([], _Port, Err, _Timeout) ->
    Err.

lookup([$u,$n,$i,$x,$: | Path], _Timeout) ->
    {ok, [{{local, Path}, local}]};
lookup(Host, Timeout) ->
    case inet:parse_address(Host) of
	{ok, IP} ->
	    {ok, [{IP, get_addr_type(IP)}]};
	{error, _} ->
	    do_lookup([{Host, Family} || Family <- [inet6, inet]],
		      [], {error, nxdomain}, Timeout)
    end.

do_lookup([{Host, Family} | HostFamilies], AddrFamilies, Err, Timeout) ->
    case inet:gethostbyname(Host, Family, Timeout) of
	{ok, HostEntry} ->
	    Addrs = host_entry_to_addrs(HostEntry),
	    AddrFamilies1 = [{Addr, Family} || Addr <- Addrs],
	    do_lookup(HostFamilies,
		      AddrFamilies ++ AddrFamilies1,
		      Err, Timeout);
	{error, _} = Err1 ->
	    do_lookup(HostFamilies, AddrFamilies, Err1, Timeout)
    end;
do_lookup([], [], Err, _Timeout) ->
    Err;
do_lookup([], AddrFamilies, _Err, _Timeout) ->
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
