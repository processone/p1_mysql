%%%-------------------------------------------------------------------
%%% File    : p1_mysql_bin.erl
%%% Author  : Pawel Chmielowski <pawel@process-one.net>
%%% Descrip.: Binary protocol and prepared statement support.

-module(p1_mysql_bin).

-export([prepare_and_execute/6]).

%%--------------------------------------------------------------------
%% External exports
%%--------------------------------------------------------------------

-include("p1_mysql.hrl").
-include("p1_mysql_consts.hrl").
-include("p1_mysql_state.hrl").
-include_lib("kernel/include/inet.hrl").

-define(MYSQL_4_0, 40). %% Support for MySQL 4.0.x
-define(MYSQL_4_1, 41). %% Support for MySQL 4.1.x et 5.0.x

-define(TYPE_DECIMAL, 0).
-define(TYPE_TINY, 1).
-define(TYPE_SHORT, 2).
-define(TYPE_LONG, 3).
-define(TYPE_FLOAT, 4).
-define(TYPE_DOUBLE, 5).
-define(TYPE_NULL, 6).
-define(TYPE_TIMESTAMP, 7).
-define(TYPE_LONGLONG, 8).
-define(TYPE_INT24, 9).
-define(TYPE_DATE, 10).
-define(TYPE_TIME, 11).
-define(TYPE_DATETIME, 12).
-define(TYPE_YEAR, 13).
%-define(TYPE_NEWDATE, 14).
-define(TYPE_VARCHAR, 15).
-define(TYPE_BIT, 16).
%-define(TYPE_TIMESTAMP2, 17).
%-define(TYPE_TIME2, 18).
%-define(TYPE_ARRAY, 19).
%-define(TYPE_INVALID, 243).
%-define	(TYPE_BOOL, 244).
-define(TYPE_JSON, 245).
-define(TYPE_NEWDECIMAL, 246).
-define(TYPE_ENUM, 247).
-define(TYPE_SET, 248).
-define(TYPE_TINY_BLOB, 249).
-define(TYPE_MEDIUM_BLOB, 250).
-define(TYPE_LONG_BLOB, 251).
-define(TYPE_BLOB, 252).
-define(TYPE_VAR_STRING, 253).
-define(TYPE_STRING, 254).
-define(TYPE_GEOMETRY, 255).

prepare_and_execute(#state{prepared = Prep} = State,
		    Query, QueryId, Args, Types, Options) ->
    case maps:get(QueryId, Prep, none) of
	none ->
	    case prepare(State, Query, QueryId, Options) of
		{ok, NState, StmtId} ->
		    NState2 = NState#state{prepared = Prep#{QueryId => StmtId}},
		    execute(NState2, StmtId, Args, Types, Options);
		{error, NState, Error} ->
		    {NState, Error}
	    end;
	StmtId ->
	    execute(State, StmtId, Args, Types, Options)
    end.

execute(#state{mysql_version = Version, log_fun = LogFun, socket = Sock} = State,
	StmtId, Args, Types, Options) ->
    Packet = generate_execute_stmt_packet(StmtId, Args, Types),
    case p1_mysql_conn:do_send(Sock, Packet, 0, LogFun) of
	ok ->
	    case get_execute_stmt_response(State, Version, Options) of
		{Tag, Result, NState2} ->
		    {NState2, {Tag, Result}};
		E -> {State, E}
	    end;
	{error, Reason} ->
	    Msg = io_lib:format("Failed sending data on socket : ~p", [Reason]),
	    {State, {error, #p1_mysql_result{error = Msg}}}
    end.

prepare(#state{mysql_version = Version, log_fun = LogFun, socket = Sock} = State,
	Query, QueryId, Options) ->
    QueryStr = if is_function(Query) -> iolist_to_binary(Query());
		   is_list(Query) -> iolist_to_binary(Query);
		   true -> Query
	       end,
    Packet = generate_prepare_packet(QueryStr),
    case p1_mysql_conn:do_send(Sock, Packet, 0, LogFun) of
	ok ->
	    case get_prepare_response(State, Version, Options) of
		{prepared, NStmtID, NState2} ->
		    Prep = NState2#state.prepared,
		    {ok, NState2#state{prepared = Prep#{QueryId => NStmtID}}};
		E -> {State, E}
	    end;
	{error, Reason} ->
	    Msg = io_lib:format("Failed sending data on socket : ~p", [Reason]),
	    {State, {error, #p1_mysql_result{error = Msg}}}
    end.

generate_execute_stmt_packet(Id, Params, ParamsType) ->
    {ParamsBin, TypesBin, _, BitMap2} = lists:foldl(
	fun({null, _}, {AccParam, AccType, Bit, BitMap}) ->
	    {AccParam, AccType, Bit*2, BitMap bor Bit};
	   ({Param, Type}, {AccParam, AccType, Bit, BitMap}) ->
	       {TypeB, ParamB} = encode_binary_value(Type, Param),
	       {<<AccParam/binary, ParamB/binary>>,
		<<AccType/binary, TypeB/binary>>,
		Bit*2, BitMap}
	end, {<<>>, <<>>, 1, 0}, lists:zip(Params, ParamsType)),

    Len = length(Params),
    LenBit = trunc((Len + 7)/8)*8,
    NullBitmapBin = <<BitMap2:LenBit>>,

    <<16#17, Id:32/little-integer, 0, 1:32/little,
      NullBitmapBin/binary, 1, TypesBin/binary, ParamsBin/binary>>.

get_execute_stmt_response(State, Version, _Options) ->
    case do_recv(State) of
	{ok, <<T:8, Rest/binary>>, _, NState} when T == 0; T == 254 ->
	    {AffectedRows, _} = decode_var_int(Rest),
	    {updated, #p1_mysql_result{affectedrows = AffectedRows}, NState};
	{ok, <<255, _ErrCode:16/little, _StateMarker:8/binary, _State:40/binary, Rest/binary>>, _, _NState}
	    when Version == ?MYSQL_4_1 ->
	    {error, #p1_mysql_result{error = binary_to_list(Rest)}};
	{ok, <<255, _ErrCode:16/little, Rest/binary>>, _, _NState} ->
	    {error, #p1_mysql_result{error = binary_to_list(Rest)}};
	{ok, Data, _, NState} ->
	    {ColumnsCount, _} = decode_var_int(Data),
	    case get_columns_definitions(NState, Version, {[], []}) of
		{ok, Columns, ColTypes, NState2} ->
		    case get_resultset_rows(NState2, ColTypes,
					    trunc((ColumnsCount + 7 + 2)/8)*8, []) of
			{ok, Rows, NState3} ->
			    {data, #p1_mysql_result{fieldinfo = Columns, rows = Rows}, NState3};
			{error, E} ->
			    {error, #p1_mysql_result{error = E}}
		    end;
		{error, E} ->
		    {error, #p1_mysql_result{error = E}}
	    end;
	{error, Reason} ->
	    {error, #p1_mysql_result{error = Reason}}
    end.

generate_prepare_packet(Query) ->
    <<16#16, Query/binary>>.

get_prepare_response(State, Version, _Options) ->
    case do_recv(State) of
	{ok, <<0, StmtID:32/little, NumColumns:16/little, NumParams:16/little, _Rest/binary>>, _, NState} ->
	    case receive_to_eof(NumParams, NState) of
		{ok, NState2} ->
		    case receive_to_eof(NumColumns, NState2) of
			{ok, NState3} ->
			    {prepared, StmtID, NState3};
			E -> E
		    end;
		E -> E
	    end;
	{ok, <<255, _ErrCode:16/little, _StateMarker:1/binary, _State:5/binary, Rest/binary>>, _, _NState}
	    when Version == ?MYSQL_4_1 ->
	    {error, #p1_mysql_result{error = binary_to_list(Rest)}};
	{ok, <<255, _ErrCode:16/little, Rest/binary>>, _, _NState} ->
	    {error, #p1_mysql_result{error = binary_to_list(Rest)}};
	{error, Reason} ->
	    {error, #p1_mysql_result{error = Reason}}
    end.

do_recv(State) ->
    p1_mysql_conn:do_recv(State#state.log_fun, State, undefined).

encode_var_string(String) ->
    <<(encode_var_int(size(String)))/binary, String/binary>>.

decode_var_string(Val) ->
    {Len, Rest} = decode_var_int(Val),
    <<Str:Len/binary, Rest2/binary>> = Rest,
    {Str, Rest2}.

encode_var_int(Val) when Val < 252 ->
    <<Val:8>>;
encode_var_int(Val) when Val < 65536 ->
    <<16#fc, Val:16/little>>;
encode_var_int(Val) when Val < 16777216 ->
    <<16#fd, Val:24/little>>;
encode_var_int(Val) ->
    <<16#fe, Val:64/little>>.

decode_var_int(<<V, Rest/binary>>) when V < 252 ->
    {V, Rest};
decode_var_int(<<252, V:16/little, Rest/binary>>) ->
    {V, Rest};
decode_var_int(<<253, V:24/little, Rest/binary>>) ->
    {V, Rest};
decode_var_int(<<254, V:64/little, Rest/binary>>) ->
    {V, Rest}.

encode_binary_value(string, Value) ->
    {<<?TYPE_VAR_STRING, 0>>, encode_var_string(Value)};
encode_binary_value(integer, Value) ->
    if
	Value > -16#80 andalso Value < 16#7f ->
	    {<<?TYPE_TINY, 0>>, <<Value:8/little-signed-integer>>};
	Value > -16#8000 andalso Value < 16#7fff ->
	    {<<?TYPE_SHORT, 0>>, <<Value:16/little-signed-integer>>};
	Value > -16#80000000 andalso Value < 16#7ffffffff ->
	    {<<?TYPE_LONG, 0>>, <<Value:32/little-signed-integer>>};
	true ->
	    {<<?TYPE_LONGLONG, 0>>, <<Value:64/little-signed-integer>>}
    end;
encode_binary_value(bool, true) ->
    {<<?TYPE_TINY, 0>>, <<1>>};
encode_binary_value(bool, false) ->
    {<<?TYPE_TINY, 0>>, <<0>>};
encode_binary_value(datetime, {{Y, M, D}, {H, MM, S}}) ->
    {<<?TYPE_DATE, 0>>, <<Y:16/little, M:8, D:8, H:8, MM:8, S:8>>}.

decode_binary_value(?TYPE_TINY, <<V, Rest/binary>>) ->
    {V, Rest};
decode_binary_value(T, <<V:16/little, Rest/binary>>) when T == ?TYPE_SHORT; T == ?TYPE_YEAR ->
    {V, Rest};
decode_binary_value(T, <<V:32/little, Rest/binary>>) when T == ?TYPE_LONG; T == ?TYPE_INT24 ->
    {V, Rest};
decode_binary_value(?TYPE_FLOAT, <<V:32/little-float, Rest/binary>>) ->
    {V, Rest};
decode_binary_value(?TYPE_DOUBLE, <<V:64/little-float, Rest/binary>>) ->
    {V, Rest};
decode_binary_value(T, <<0, Rest/binary>>) when
    T == ?TYPE_TIMESTAMP; T == ?TYPE_DATETIME; T == ?TYPE_DATE ->
    {{{0, 0, 0}, {0, 0, 0, 0}}, Rest};
decode_binary_value(T, <<4, Y:16/little, M, D, Rest/binary>>) when
    T == ?TYPE_TIMESTAMP; T == ?TYPE_DATETIME; T == ?TYPE_DATE ->
    {{{Y, M, D}, {0, 0, 0, 0}}, Rest};
decode_binary_value(T, <<7, Y:16/little, M, D, H, _MM, S, Rest/binary>>) when
    T == ?TYPE_TIMESTAMP; T == ?TYPE_DATETIME; T == ?TYPE_DATE ->
    {{{Y, M, D}, {H, M, S, 0}}, Rest};
decode_binary_value(T, <<11, Y:16/little, M, D, H, _MM, S, MS:32/little, Rest/binary>>)
    when T == ?TYPE_TIMESTAMP; T == ?TYPE_DATETIME; T == ?TYPE_DATE ->
    {{{Y, M, D}, {H, M, S, MS}}, Rest};
decode_binary_value(?TYPE_LONGLONG, <<V:64/little, Rest/binary>>) ->
    {V, Rest};
decode_binary_value(?TYPE_TIME, <<0, Rest/binary>>) ->
    {{0, 0, 0, 0, 0, 0}, Rest};
decode_binary_value(?TYPE_TIME, <<8, Neg, D:32/little, H, M, S, Rest/binary>>) ->
    {{Neg, D, H, M, S, 0}, Rest};
decode_binary_value(?TYPE_TIME, <<12, Neg, D:32/little, H, M, S, MS:32/little, Rest/binary>>) ->
    {{Neg, D, H, M, S, MS}, Rest};
decode_binary_value(T, Rest) when
    T == ?TYPE_VARCHAR; T == ?TYPE_VAR_STRING; T == ?TYPE_STRING; T == ?TYPE_STRING;
    T == ?TYPE_ENUM; T == ?TYPE_SET;
    T == ?TYPE_BLOB; T == ?TYPE_TINY_BLOB; T == ?TYPE_MEDIUM_BLOB; T == ?TYPE_LONG_BLOB;
    T == ?TYPE_GEOMETRY; T == ?TYPE_JSON;
    T == ?TYPE_DECIMAL; T == ?TYPE_NEWDECIMAL ->
    {Str, Rest2} = decode_var_string(Rest),
    case T of
	%_ when T == ?TYPE_DECIMAL; T == ?TYPE_NEWDECIMAL ->
	%    {catch binary_to_float(Str), Rest2};
	_ ->
	    {Str, Rest2}
    end.

decode_column_41(Data) ->
    {_Catalog, Rest} = decode_var_string(Data),
    {_Schema, Rest1} = decode_var_string(Rest),
    {Table, Rest2} = decode_var_string(Rest1),
    {_OrgTable, Rest3} = decode_var_string(Rest2),
    {Name, Rest4} = decode_var_string(Rest3),
    {_OrgName, <<12, _CharSet:16/little, _ColLen:32/little, Type:8,
		 _Flags:16/little, _Decimals:8, _Rest7/binary>>} = decode_var_string(Rest4),
    {{Table, Name, 1, p1_mysql_conn:get_field_datatype(Type)}, Type}.

decode_column_32(Data) ->
    {Table, Rest} = decode_var_string(Data),
    {Name, <<1, Type:8, 3, _Flags:16/little, _Decimals:8, _Rest1/binary>>} = decode_var_string(Rest),
    {{Table, Name, 1, p1_mysql_conn:get_field_datatype(Type)}, Type}.

get_columns_definitions(State, Version, {Acc1, Acc2}) ->
    case do_recv(State) of
	{ok, <<254, _/binary>>, _, NState} ->
	    {ok, lists:reverse(Acc1), lists:reverse(Acc2), NState};
	{ok, Data, _, NState} ->
	    case Version of
		?MYSQL_4_1 ->
		    {Column, ColType} = decode_column_41(Data),
		    get_columns_definitions(NState, Version, {[Column | Acc1], [ColType | Acc2]});
		_ ->
		    {Column, ColType} = decode_column_32(Data),
		    get_columns_definitions(NState, Version, {[Column | Acc1], [ColType | Acc2]})
	    end;
	{error, Reason} ->
	    {error, Reason}
    end.

decode_resultset_row([], _ColumnsCount, _Null, Value, Acc) ->
    {lists:reverse(Acc), Value};
decode_resultset_row([Type | TypeRest], Column, Null, Value, Acc) ->
    case (1 bsl Column) band Null of
	1 ->
	    decode_resultset_row(TypeRest, Column + 1, Null, Value, [null | Acc]);
	_ ->
	    {Val, Rest} = decode_binary_value(Type, Value),
	    decode_resultset_row(TypeRest, Column + 1, Null, Rest, [Val | Acc])
    end.

get_resultset_rows(State, Columns, NullSize, Acc) ->
    case do_recv(State) of
	{ok, <<254, _/binary>>, _, NState} ->
	    {ok, lists:reverse(Acc), NState};
	{ok, <<0, Null:NullSize/little, Values/binary>>, _, NState} ->
	    %io:format("ROWS: ~p ~p ~p~n", [Null, NullSize, Values]),
	    {Row, _Rest} = decode_resultset_row(Columns, 0, Null, Values, []),
	    get_resultset_rows(NState, Columns, NullSize, [Row | Acc]);
	{error, Reason} ->
	    {error, Reason}
    end.

receive_to_eof(0, State) ->
    {ok, State};
receive_to_eof(N, State) ->
    case do_recv(State) of
	{ok, <<254, _/binary>>, _, NState} ->
	    {ok, NState};
	{ok, _, _, NState} ->
	    receive_to_eof(N, NState);
	{error, Reason} ->
	    {error, Reason}
    end.
