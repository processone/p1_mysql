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
	 stop/1
	]).

%%--------------------------------------------------------------------
%% External exports (should only be used by the 'p1_mysql_auth' module)
%%--------------------------------------------------------------------
-export([do_recv/3
	]).

-include("p1_mysql.hrl").
-include("p1_mysql_consts.hrl").

-record(state, {
	  mysql_version,
	  log_fun,
	  recv_pid,
	  socket,
	  data
	 }).

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
    ConnPid = self(),
    Pid = spawn(fun () ->
			init(Host, Port, User, Password, Database,
			     ConnectTimeout, LogFun, ConnPid, SSLOpts)
		end),
    post_start(Pid, ConnectTimeout, LogFun).

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
    ConnPid = self(),
    Pid = spawn_link(fun () ->
			init(Host, Port, User, Password, Database,
			     ConnectTimeout, LogFun, ConnPid, SSLOpts)
		end),
    post_start(Pid, ConnectTimeout, LogFun).

%% part of start/6 or start_link/6:
post_start(Pid, ConnectTimeout, _LogFun) ->
    %%Timeout = get_option(timeout, Options, ?DEFAULT_STANDALONE_TIMEOUT),
    %%TODO find a way to get configured Options here
    Timeout = if is_integer(ConnectTimeout) -> ConnectTimeout;
		 true -> ?DEFAULT_STANDALONE_TIMEOUT
	      end,
    receive
	{p1_mysql_conn, Pid, ok} ->
	    {ok, Pid};
	{p1_mysql_conn, Pid, {error, Reason}} ->
	    p1_mysql:log(_LogFun, error, "p1_mysql_conn: post_start error ~p~n",
		      [Reason]),
	    stop(Pid),
	    {error, Reason}
%	Unknown ->
%	    p1_mysql:log(_LogFun, error, "p1_mysql_conn: Received unknown signal, exiting"),
%	    p1_mysql:log(_LogFun, debug, "p1_mysql_conn: Unknown signal : ~p", [Unknown]),
%	    {error, "unknown signal received"}
    after Timeout ->
	    p1_mysql:log(_LogFun, error, "p1_mysql_conn: post_start timeout~n",
		      []),
	    stop(Pid),
	    timer:sleep(100),
	    catch exit(Pid, kill),
	    {error, "timed out"}
    end.

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
    TRef = erlang:start_timer(Timeout, self(), timeout),
    Pid ! {fetch, TRef, Query, From, Options},
    case From of
	Self ->
	    %% We are not using a mysql_dispatcher, await the response
	    wait_fetch_result(TRef, Pid);
	_ ->
	    %% From is gen_server From, Pid will do gen_server:reply()
	    %% when it has an answer
	    ok
    end.

wait_fetch_result(TRef, Pid) ->
    receive
	{fetch_result, TRef, Pid, Result} ->
	    case erlang:cancel_timer(TRef) of
		false ->
		    receive
			{timeout, TRef, _} ->
			    ok
		    after 0 ->
			    ok
		    end;
		_ ->
		    ok
	    end,
	    Result;
	{fetch_result, _BadRef, Pid, _Result} ->
	    wait_fetch_result(TRef, Pid);
	{timeout, TRef, _Info} ->
	    stop(Pid),
	    {error, #p1_mysql_result{error="query timed out"}}
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
do_recv(LogFun, RecvPid, SeqNum) when is_function(LogFun);
				      LogFun == undefined,
				      SeqNum == undefined ->
    receive
        {p1_mysql_recv, RecvPid, data, Packet, Num} ->
            %%p1_mysql:log(LogFun, debug, "p1_mysql_conn: recv packet ~p:
            %%~p", [Num, Packet]),
	    {ok, Packet, Num};
	{p1_mysql_recv, RecvPid, closed, _E} ->
	    p1_mysql:log(LogFun, error, "p1_mysql_conn: p1_mysql_recv:"
		      " socket was closed ~p~n", [{RecvPid, _E}]),
	    {error, "p1_mysql_recv: socket was closed"};
	close ->
	    p1_mysql:log(LogFun, error, "p1_mysql_conn: p1_mysql_recv:"
					" received close~n", []),
	    {error, "p1_mysql_recv: socket was closed"}
    end;
do_recv(LogFun, RecvPid, SeqNum) when is_function(LogFun);
				      LogFun == undefined,
				      is_integer(SeqNum) ->
    ResponseNum = SeqNum + 1,
    receive
        {p1_mysql_recv, RecvPid, data, Packet, ResponseNum} ->
            %%p1_mysql:log(LogFun, debug, "p1_mysql_conn: recv packet ~p:
            %%~p", [ResponseNum, Packet]),
	    {ok, Packet, ResponseNum};
	{p1_mysql_recv, RecvPid, closed, _E} ->
	    p1_mysql:log(LogFun, error, "p1_mysql_conn: p1_mysql_recv:"
		      " socket was closed 2 ~p~n", [{RecvPid, _E}]),
	    {error, "p1_mysql_recv: socket was closed"};
	close ->
	    p1_mysql:log(LogFun, error, "p1_mysql_conn: p1_mysql_recv:"
					" received close~n", []),
	    {error, "p1_mysql_recv: socket was closed"}
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
init(Host, Port, User, Password, Database, ConnectTimeout, LogFun, Parent, SSLOpts) ->
    case p1_mysql_recv:start_link(Host, Port, ConnectTimeout, LogFun, self(), SSLOpts) of
	{ok, RecvPid, Sock0} ->
	    case mysql_init(Sock0, RecvPid, User, Password, LogFun, SSLOpts) of
		{ok, {SockMod, RawSock} = Sock, Version} ->
		    case do_query(Sock, RecvPid, LogFun, "use " ++ Database,
				  Version, [{result_type, binary}]) of
			{error, MySQLRes} ->
			    p1_mysql:log(LogFun, error,
				      "p1_mysql_conn: Failed changing"
				      " to database ~p : ~p",
				      [Database,
				       p1_mysql:get_result_reason(MySQLRes)]),
			    SockMod:close(RawSock),
			    Parent ! {p1_mysql_conn, self(),
				      {error, failed_changing_database}};
			%% ResultType: data | updated
			{_ResultType, _MySQLRes} ->
			    Parent ! {p1_mysql_conn, self(), ok},
			    State = #state{mysql_version=Version,
					   recv_pid = RecvPid,
					   socket   = Sock,
					   log_fun  = LogFun,
					   data     = <<>>
					  },
			    loop(State)
		    end;
		{error, _Reason} ->
		    Parent ! {p1_mysql_conn, self(), {error, login_failed}}
	    end;
	E ->
	    p1_mysql:log(LogFun, error, "p1_mysql_conn: "
		      "Failed connecting to ~p:~p : ~p",
		      [Host, Port, E]),
	    Parent ! {p1_mysql_conn, self(), {error, connect_failed}}
    end.

%%--------------------------------------------------------------------
%% Function: loop(State)
%%           State = state record()
%% Descrip.: Wait for signals asking us to perform a MySQL query, or
%%           signals that the socket was closed.
%% Returns : error | does not return
%%--------------------------------------------------------------------
loop(State) ->
    RecvPid = State#state.recv_pid,
    receive
	{fetch, Ref, Query, GenSrvFrom, Options} ->
	    %% GenSrvFrom is either a gen_server:call/3 From term(),
	    %% or a pid if no gen_server was used to make the query
	    Res = do_query(State, Query, Options),
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
		{error, #p1_mysql_result{error="p1_mysql_recv: socket was closed"}} ->
		    p1_mysql:log(State#state.log_fun, error, "p1_mysql_conn: "
							     "Connection closed, exiting.", []),
		    close_connection(State);
		_ ->
		    loop(State)
	    end;
	{p1_mysql_recv, RecvPid, data, Packet, Num} ->
	    p1_mysql:log(State#state.log_fun, error, "p1_mysql_conn: "
		      "Received MySQL data when not expecting any "
		      "(num ~p) - ignoring it", [Num]),
	    p1_mysql:log(State#state.log_fun, error, "p1_mysql_conn: "
		      "Unexpected MySQL data (num ~p) :~n~p",
		      [Num, Packet]),
	    loop(State);
        {p1_mysql_recv, RecvPid, closed, _Reason} ->
            p1_mysql:log(State#state.log_fun, error, "p1_mysql_conn: "
                         "Connection closed, exiting.", []),
            close_connection(State);
	close ->
	    p1_mysql:log(State#state.log_fun, info, "p1_mysql_conn: "
		      "Received close signal, exiting.", []),
	    close_connection(State);
        Unknown ->
	    p1_mysql:log(State#state.log_fun, error, "p1_mysql_conn: "
		      "Received unknown signal, exiting : ~p",
		      [Unknown]),
	    close_connection(State),
	    error
    end.

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
mysql_init(Sock, RecvPid, User, Password, LogFun, SSLOpts) ->
    case do_recv(LogFun, RecvPid, undefined) of
	{ok, Packet, InitSeqNum} ->
	    {Version, Salt, Caps, AuthPlug} = greeting(Packet, LogFun),
	    case Caps band ?CLIENT_SSL of
		0 ->
		    case proplists:get_bool(ssl_required, SSLOpts) of
			true ->
			    p1_mysql:log(LogFun, error, "p1_mysql_conn: "
							"init failed - ssl required, but not available~n",
					 []),
			    {error, "SSL not available"};
			false ->
			    authenticate({gen_tcp, Sock}, RecvPid, User, Password, LogFun,
					 InitSeqNum, Version, Salt, Caps, AuthPlug)
		    end;
		_ ->
		    case proplists:get_bool(ssl, SSLOpts) orelse proplists:get_bool(ssl_required, SSLOpts) of
			true ->
			    case start_ssl(Sock, RecvPid, LogFun, InitSeqNum+1, AuthPlug) of
				{ok, NewSock} ->
				    authenticate(NewSock, RecvPid, User, Password, LogFun,
						 InitSeqNum+1, Version, Salt, Caps, AuthPlug);
				{error, Reason} ->
				    {error, Reason}
			    end;
			_ ->
			    authenticate({gen_tcp, Sock}, RecvPid, User, Password, LogFun,
					 InitSeqNum, Version, Salt, Caps, AuthPlug)
		    end
	    end;
	{error, Reason} ->
	    {error, Reason}
    end.

%% part of mysql_init/4

start_ssl(Sock, RecvPid, LogFun, SeqNum, AuthPlug) ->
    Packet = p1_mysql_auth:get_auth_head(AuthPlug, ?CLIENT_SSL),
    Data = <<(size(Packet)):24/little, SeqNum:8, Packet/binary>>,
    p1_mysql:log(LogFun, debug, "p1_mysql_conn send start ssl ~p: ~p", [SeqNum, Packet]),
    gen_tcp:send(Sock, Data),
    RecvPid ! {start_ssl},
    receive
	{p1_mysql_recv, RecvPid, ssl, {ok, SSLSock}} ->
	    {ok, {ssl, SSLSock}};
	{p1_mysql_recv, RecvPid, ssl, {error, Reason}} ->
	    p1_mysql:log(LogFun, error, "p1_mysql_conn: "
					"ssl start failed: ~p~n",
			 [Reason]),
	    {error, "ssl failed"}
    end.

authenticate(Sock, RecvPid, User, Password, LogFun, SeqNum,
	     Version, Salt, Caps, AuthPlug) ->
    AuthRes = p1_mysql_auth:do_auth(AuthPlug, Sock, RecvPid,
				    SeqNum + 1,
				    User, Password,
				    Salt, Caps, LogFun),
    case AuthRes of
	{ok, <<0:8, _Rest/binary>>, _RecvNum} ->
	    {ok, Sock, Version};
	{ok, <<255:8, Code:16/little, Message/binary>>, _RecvNum} ->
	    p1_mysql:log(LogFun, error, "p1_mysql_conn: "
					"init error ~p: ~p~n",
			 [Code, binary_to_list(Message)]),
	    {error, binary_to_list(Message)};
	{ok, RecvPacket, _RecvNum} ->
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
	    {?MYSQL_4_0, Salt, 0, "old_pass"};
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
	    {?MYSQL_4_1, Salt, Caps, AuthPlug}
    end.

%% part of greeting/2
asciz(Data) when is_binary(Data) ->
    p1_mysql:asciz_binary(Data, []);
asciz(Data) when is_list(Data) ->
    {String, [0 | Rest]} = lists:splitwith(fun (C) ->
						   C /= 0
					   end, Data),
    {String, Rest}.

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
get_query_response(LogFun, RecvPid, Version, Options) ->
    case do_recv(LogFun, RecvPid, undefined) of
	{ok, <<Fieldcount:8, Rest/binary>>, _} ->
	    case Fieldcount of
		0 ->
		    %% No Tabular data
		    AffectedRows = case Rest of
			<<16#fc, Value:16/little, _/binary>> -> Value;
			<<16#fd, Value:24/little, _/binary>> -> Value;
			<<16#fe, Value:64/little, _/binary>> -> Value;
			<<Value:8, _/binary>> -> Value
		    end,
		    {updated, #p1_mysql_result{affectedrows=AffectedRows}};
		255 ->
		    <<_Code:16/little, Message/binary>>  = Rest,
		    {error, #p1_mysql_result{error=binary_to_list(Message)}};
		_ ->
		    %% Tabular data received
                    ResultType = get_option(result_type, Options, ?DEFAULT_RESULT_TYPE),
		    case get_fields(LogFun, RecvPid, [], Version, ResultType) of
			{ok, Fields} ->
			    case get_rows(Fieldcount, LogFun, RecvPid, ResultType, []) of
				{ok, Rows} ->
				    {data, #p1_mysql_result{fieldinfo=Fields,
							 rows=Rows}};
				{error, Reason} ->
				    {error, #p1_mysql_result{error=Reason}}
			    end;
			{error, Reason} ->
			    {error, #p1_mysql_result{error=Reason}}
		    end
	    end;
	{error, Reason} ->
	    {error, #p1_mysql_result{error=Reason}}
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
get_fields(LogFun, RecvPid, Res, ?MYSQL_4_0, ResultType) ->
    case do_recv(LogFun, RecvPid, undefined) of
	{ok, Packet, _Num} ->
	    case Packet of
		<<254:8>> ->
		    {ok, lists:reverse(Res)};
		<<254:8, Rest/binary>> when size(Rest) < 8 ->
		    {ok, lists:reverse(Res)};
		_ ->
		    {Table, Rest} = get_with_length(Packet),
		    {Field, Rest2} = get_with_length(Rest),
		    {LengthB, Rest3} = get_with_length(Rest2),
		    LengthL = size(LengthB) * 8,
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
		    get_fields(LogFun, RecvPid, [This | Res],
                               ?MYSQL_4_0, ResultType)
	    end;
	{error, Reason} ->
	    {error, Reason}
    end;
%% Support for MySQL 4.1.x and 5.x:
get_fields(LogFun, RecvPid, Res, ?MYSQL_4_1, ResultType) ->
    case do_recv(LogFun, RecvPid, undefined) of
	{ok, Packet, _Num} ->
	    case Packet of
		<<254:8>> ->
		    {ok, lists:reverse(Res)};
		<<254:8, Rest/binary>> when size(Rest) < 8 ->
		    {ok, lists:reverse(Res)};
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
		    get_fields(LogFun, RecvPid, [This | Res],
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
get_rows(N, LogFun, RecvPid, ResultType, Res) ->
    case do_recv(LogFun, RecvPid, undefined) of
	{ok, Packet, _Num} ->
	    case Packet of
		<<254:8, Rest/binary>> when size(Rest) < 8 ->
		    {ok, lists:reverse(Res)};
		_ ->
		    {ok, This} = get_row(N, Packet, ResultType, []),
		    get_rows(N, LogFun, RecvPid, ResultType, [This | Res])
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

close_connection(State) ->
    {SockMod, Socket} = State#state.socket,
    Result = SockMod:close(Socket),
    p1_mysql:log(State#state.log_fun,  normal, "Closing connection ~p: ~p~n",
	      [State#state.socket, Result]),
    Result.


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
do_query(State, Query, Options) when is_record(State, state) ->
    do_query(State#state.socket,
	     State#state.recv_pid,
	     State#state.log_fun,
	     Query,
	     State#state.mysql_version,
	     Options
	    ).

do_query(Sock, RecvPid, LogFun, Query, Version, Options) when is_pid(RecvPid),
							      (is_list(Query) or is_binary(Query)) ->
    Packet = list_to_binary([?MYSQL_QUERY_OP, Query]),
    case do_send(Sock, Packet, 0, LogFun) of
	ok ->
	    get_query_response(LogFun, RecvPid, Version, Options);
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
    %%p1_mysql:log(LogFun, debug, "p1_mysql_conn: send packet ~p: ~p",
    %%[SeqNum, Data]),
    SockMod:send(Sock, Data).

%%--------------------------------------------------------------------
%% Function: get_field_datatype(DataType)
%%           DataType = integer(), MySQL datatype
%% Descrip.: Return MySQL field datatype as description string
%% Returns : String, MySQL datatype
%%--------------------------------------------------------------------
get_field_datatype(0) ->   'DECIMAL';
get_field_datatype(1) ->   'TINY';
get_field_datatype(2) ->   'SHORT';
get_field_datatype(3) ->   'LONG';
get_field_datatype(4) ->   'FLOAT';
get_field_datatype(5) ->   'DOUBLE';
get_field_datatype(6) ->   'NULL';
get_field_datatype(7) ->   'TIMESTAMP';
get_field_datatype(8) ->   'LONGLONG';
get_field_datatype(9) ->   'INT24';
get_field_datatype(10) ->  'DATE';
get_field_datatype(11) ->  'TIME';
get_field_datatype(12) ->  'DATETIME';
get_field_datatype(13) ->  'YEAR';
get_field_datatype(14) ->  'NEWDATE';
get_field_datatype(16) ->  'BIT';
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
