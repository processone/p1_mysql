%%%-------------------------------------------------------------------
%%% File    : p1_mysql_auth.erl
%%% Author  : Fredrik Thulin <ft@it.su.se>
%%% Descrip.: MySQL client authentication functions.
%%% Created :  4 Aug 2005 by Fredrik Thulin <ft@it.su.se>
%%%
%%% Note    : All MySQL code was written by Magnus Ahltorp, originally
%%%           in the file p1_mysql.erl - I just moved it here.
%%%
%%% Copyright (c) 2001-2004 Kungliga Tekniska Högskolan
%%% See the file COPYING
%%%
%%%-------------------------------------------------------------------
-module(p1_mysql_auth).

%%--------------------------------------------------------------------
%% External exports (should only be used by the 'p1_mysql_conn' module)
%%--------------------------------------------------------------------
-export([do_auth/8, password_sha2/2, get_auth_head/2]).

-include("p1_mysql_consts.hrl").
-include("p1_mysql_state.hrl").

%%--------------------------------------------------------------------
%% Macros
%%--------------------------------------------------------------------
-define(LONG_PASSWORD, 1).
-define(FOUND_ROWS, 2).
-define(LONG_FLAG, 4).
-define(PROTOCOL_41, 512).
-define(TRANSACTIONS, 8192).
-define(SECURE_CONNECTION, 32768).
-define(CONNECT_WITH_DB, 8).

-define(MAX_PACKET_SIZE, 1000000).

%%====================================================================
%% External functions
%%====================================================================

get_auth_head("old_auth", ExtraCaps) ->
    make_auth_head(ExtraCaps);
get_auth_head("mysql_native_password", ExtraCaps) ->
    make_new_auth_head(none, "", ExtraCaps);
get_auth_head(Type, ExtraCaps) ->
    make_new_auth_head(none, Type, ExtraCaps).

%%--------------------------------------------------------------------
%% Function: do_auth(Type, Sock, RecvPid, SeqNum, User, Password, Salt1,
%%                   Salt2, LogFun)
%%           Type     = string(), authentication method offered by server
%%           Sock     = term(), gen_tcp socket
%%           RecvPid  = pid(), receiver process pid
%%           SeqNum   = integer(), first sequence number we should use
%%           User     = string(), MySQL username
%%           Password = string(), MySQL password
%%           Salt     = string(), salt from server greeting
%%           Caps     = integer(), server capabilities
%%           LogFun   = undefined | function() of arity 3
%% Descrip.: Perform MySQL authentication.
%% Returns : result of p1_mysql_conn:do_recv/3
%%--------------------------------------------------------------------
do_auth("old_auth", State, SeqNum, User, Password,
	Salt, _Caps, LogFun) ->
    Auth = password_old(Password, Salt),
    Packet2 = make_auth(User, Auth),
    do_send(State, Packet2, SeqNum, LogFun),
    p1_mysql_conn:do_recv(LogFun, State, SeqNum);
do_auth("mysql_native_password", State, SeqNum, User, Password,
	Salt, Caps, LogFun) when Caps band ?CLIENT_PLUGIN_AUTH == 0 ->
    Auth = password_new(Password, Salt),
    Packet2 = make_new_auth(User, Auth, none, ""),
    do_send(State, Packet2, SeqNum, LogFun),
    case p1_mysql_conn:do_recv(LogFun, State, SeqNum) of
	{ok, Packet3, SeqNum2, NState} ->
	    case Packet3 of
		<<254:8>> ->
		    AuthOld = password_old(Password, string:substr(Salt, 1, 8)),
		    do_send(NState, <<AuthOld/binary, 0:8>>, SeqNum2 + 1, LogFun),
		    p1_mysql_conn:do_recv(LogFun, NState, SeqNum2 + 1);
		_ ->
		    {ok, Packet3, SeqNum2, NState}
	    end;
	{error, Reason} ->
	    {error, Reason}
    end;
do_auth(Type, State, SeqNum, User, Password,
	Salt, Caps, LogFun)
    when Caps band ?CLIENT_PLUGIN_AUTH /= 0 andalso
	 (Type == "mysql_native_password" orelse
	  Type == "caching_sha2_password" orelse
	  Type == "sha256_password") ->
    Auth = case {State#state.socket, Type} of
	       {_, "mysql_native_password"} ->
		   password_new(Password, Salt);
	       {{ssl, _}, "sha256_password"} ->
		   <<(iolist_to_binary(Password))/binary, 0>>;
	       {_, "sha256_password"} ->
		   <<1>>;
	       _ ->
		   password_sha2(Password, Salt)
	   end,
    Packet2 = make_new_auth(User, Auth, none, Type),
    do_send(State, Packet2, SeqNum, LogFun),
    check_for_auth_switch(State, SeqNum, Password, Salt, Type, LogFun);
do_auth(Type, _State, _SeqNum, _User, _Password,
	_Salt, _Caps, LogFun) ->
    p1_mysql:log(LogFun, error, "p1_mysql_auth: do_auth: "
				"Unknown authentication method ~s", [Type]),
    Err = lists:flatten(io_lib:format("p1_mysql_auth: Unknown "
				      "authentication method ~s", [Type])),
    {error, Err}.

check_for_auth_switch(State, SeqNum, Password, Salt, Type, LogFun) ->
    case p1_mysql_conn:do_recv(LogFun, State, SeqNum) of
	{ok, Packet3, SeqNum2, NState} ->
	    case Packet3 of
		<<254:8, Rest/binary>> ->
		    {TypeNew, SaltNew} = p1_mysql:asciz_binary(Rest, []),
		    Len = size(SaltNew) - 1,
		    <<SaltNew2:Len/binary, _/binary>> = SaltNew,
		    p1_mysql:log(LogFun, debug, "p1_mysql_auth: do_auth: "
						"Protocol change ~p ~p",
				 [TypeNew, SaltNew2]),
		    do_auth_switch(TypeNew, NState, SeqNum2 + 1,
				   Password, SaltNew2, LogFun);
		<<1:8, PublicKey/binary>> when Type == "sha256_password" ->
		    case calculate_rsa_password(PublicKey, Password, Salt, LogFun) of
			{ok, RSAPassword} ->
			    do_send(NState, RSAPassword, SeqNum2 + 1, LogFun),
			    p1_mysql_conn:do_recv(LogFun, NState, SeqNum2 + 1);
			E ->
			    E
		    end;
		<<1:8, 4:8>> ->
		    case get_rsa_password(NState, SeqNum2 + 1, <<2>>, Password, Salt, LogFun) of
			{error, _} = E ->
			    E;
			{ok, NState2, RSAPassword, SeqNum3} ->
			    do_send(NState2, RSAPassword, SeqNum3, LogFun),
			    p1_mysql_conn:do_recv(LogFun, NState2, SeqNum3)
		    end;
		<<1:8, 3:8>> ->
		    p1_mysql_conn:do_recv(LogFun, NState, SeqNum2);
		_ ->
		    {ok, Packet3, SeqNum2, NState}
	    end;
	{error, Reason} ->
	    {error, Reason}
    end.

do_auth_switch("mysql_native_password", State, SeqNum, Password, Salt, LogFun) ->
    do_send(State, password_new(Password, Salt), SeqNum, LogFun),
    p1_mysql_conn:do_recv(LogFun, State, SeqNum);
do_auth_switch("caching_sha2_password", State, SeqNum, Password, Salt, LogFun) ->
    do_send(State, password_sha2(Password, Salt), SeqNum, LogFun),
    check_for_auth_switch(State, SeqNum, Password, Salt, "caching_sha2_password", LogFun);
do_auth_switch("sha256_password", State, SeqNum, Password, Salt, LogFun) ->
    case get_rsa_password(State, SeqNum, <<1>>, Password, Salt, LogFun) of
	{error, _} = E ->
	    E;
	{ok, NState2, RSAPassword, SeqNum3} ->
	    do_send(NState2, RSAPassword, SeqNum3, LogFun),
	    p1_mysql_conn:do_recv(LogFun, NState2, SeqNum3)
    end;
do_auth_switch(Type, _Sock, _SeqNum, _Password, _Salt, LogFun) ->
    p1_mysql:log(LogFun, error, "p1_mysql_auth: do_auth_switch: "
				"Unknown authentication method ~s", [Type]),
    Err = lists:flatten(io_lib:format("p1_mysql_auth: Server request switch to unknown "
				      "authentication method ~s", [Type])),
    {error, Err}.

get_rsa_password(#state{socket = {ssl, _}} = State, SeqNum, _Type, Password, _Salt, _LogFun) ->
    {ok, State, <<(iolist_to_binary(Password))/binary, 0>>, SeqNum};
get_rsa_password(State, SeqNum, Type, Password, Salt, LogFun) ->
    do_send(State, Type, SeqNum, LogFun),
    case p1_mysql_conn:do_recv(LogFun, State, SeqNum) of
	{ok, <<1:8, PublicKey/binary>>, SeqNum2, NState} ->
	    case calculate_rsa_password(PublicKey, Password, Salt, LogFun) of
		{ok, Encrypted} ->
		    {ok, NState, Encrypted, SeqNum2 + 1};
		E ->
		    E
	    end;
	{ok, PacketUnk, _, _} ->
	    p1_mysql:log(LogFun, error, "p1_mysql_auth: do_publickey_auth: "
					"Unknown response to public key request ~p", [PacketUnk]),
	    {error, "p1_mysql_auth: Unknown response to public key request"};
	{error, Err} ->
	    p1_mysql:log(LogFun, error, "p1_mysql_auth: do_publickey_auth: "
					"Error response to public key request ~p", [Err]),
	    {error, Err}
    end.

calculate_rsa_password(PublicKey, Password, Salt, LogFun) ->
    case public_key:pem_decode(PublicKey) of
	[{'SubjectPublicKeyInfo', _, _} = KeyInfo | _] ->
	    Key = public_key:pem_entry_decode(KeyInfo),
	    PassB = <<(iolist_to_binary(Password))/binary, 0:8>>,
	    PLen = size(PassB),
	    PLenBits = PLen*8,
	    SaltB = repeat_bin(iolist_to_binary(Salt), PLen),
	    <<PassN:PLenBits>> = PassB,
	    <<SaltN:PLenBits>> = SaltB,
	    Xor = <<(PassN bxor SaltN):PLenBits>>,
	    Encrypted = public_key:encrypt_public(Xor, Key,
						  [{rsa_pad, rsa_pkcs1_oaep_padding}]),
	    {ok, Encrypted};
	_ ->
	    p1_mysql:log(LogFun, error, "p1_mysql_auth: do_publickey_auth: "
					"Can't decode public key", []),
	    {error, "p1_mysql_auth: do_publickey_auth: Can't decode public key"}
    end.

repeat_bin(Bin, Len) when size(Bin) >= Len ->
    binary:part(Bin, 0, Len);
repeat_bin(Bin, Len) when size(Bin) < Len ->
    repeat_bin(<<Bin/binary, Bin/binary>>, Len).

%%====================================================================
%% Internal functions
%%====================================================================

password_old(Password, Salt) ->
    {P1, P2} = hash(Password),
    {S1, S2} = hash(Salt),
    Seed1 = P1 bxor S1,
    Seed2 = P2 bxor S2,
    List = rnd(9, Seed1, Seed2),
    {L, [Extra]} = lists:split(8, List),
    list_to_binary(lists:map(fun (E) ->
				     E bxor (Extra - 64)
			     end, L)).

%% part of do_old_auth/4, which is part of mysql_init/4
make_auth_head(ExtraCaps) ->
    Caps = ?LONG_PASSWORD bor ?LONG_FLAG
	   bor ?TRANSACTIONS bor ?FOUND_ROWS bor
	   ExtraCaps,
    Maxsize = 0,
    <<Caps:16/little, Maxsize:24/little>>.

make_auth(User, Password) ->
    Head = make_auth_head(0),
    UserB = list_to_binary(User),
    PasswordB = Password,
    <<Head/binary, UserB/binary, 0:8, PasswordB/binary>>.

%% part of do_new_auth/4, which is part of mysql_init/4
make_new_auth_head(_Database, AuthMethod, ExtraCaps) ->
    DBCaps = 0,
    AuthCaps = case AuthMethod of
			    "" -> 0;
			    _ -> ?CLIENT_PLUGIN_AUTH
			end,
    Caps = ?CLIENT_LONG_PASSWORD bor ?CLIENT_LONG_FLAG bor
	   ?CLIENT_TRANSACTIONS bor ?CLIENT_PROTOCOL_41 bor
	   ?CLIENT_FOUND_ROWS bor ?CLIENT_RESERVED2 bor
	   DBCaps bor AuthCaps bor ExtraCaps,
    Maxsize = ?MAX_PACKET_SIZE,
    <<Caps:32/little, Maxsize:32/little, 8:8, 0:23/integer-unit:8>>.

make_new_auth(User, Password, Database, AuthMethod) ->
    Head = make_new_auth_head(Database, AuthMethod, 0),
    DatabaseB = <<>>,
    AuthB = case AuthMethod of
			    "" -> <<>>;
			    _ -> <<(list_to_binary(AuthMethod))/binary, 0>>
	       end,
    UserB = list_to_binary(User),
    PasswordL = size(Password),
    <<Head/binary, UserB/binary, 0:8, PasswordL:8, Password/binary,
      DatabaseB/binary, AuthB/binary>>.

hash(S) ->
    hash(S, 1345345333, 305419889, 7).

hash([C | S], N1, N2, Add) ->
    N1_1 = N1 bxor (((N1 band 63) + Add) * C + N1 * 256),
    N2_1 = N2 + ((N2 * 256) bxor N1_1),
    Add_1 = Add + C,
    hash(S, N1_1, N2_1, Add_1);
hash([], N1, N2, _Add) ->
    Mask = (1 bsl 31) - 1,
    {N1 band Mask , N2 band Mask}.

rnd(N, Seed1, Seed2) ->
    Mod = (1 bsl 30) - 1,
    rnd(N, [], Seed1 rem Mod, Seed2 rem Mod).

rnd(0, List, _, _) ->
    lists:reverse(List);
rnd(N, List, Seed1, Seed2) ->
    Mod = (1 bsl 30) - 1,
    NSeed1 = (Seed1 * 3 + Seed2) rem Mod,
    NSeed2 = (NSeed1 + Seed2 + 33) rem Mod,
    Float = (float(NSeed1) / float(Mod))*31,
    Val = trunc(Float)+64,
    rnd(N - 1, [Val | List], NSeed1, NSeed2).



dualmap(_F, [], []) ->
    [];
dualmap(F, [E1 | R1], [E2 | R2]) ->
    [F(E1, E2) | dualmap(F, R1, R2)].

bxor_binary(B1, B2) ->
    list_to_binary(dualmap(fun (E1, E2) ->
				   E1 bxor E2
			   end, binary_to_list(B1), binary_to_list(B2))).

password_new(Password, Salt) ->
    Stage1 = crypto:hash(sha, Password),
    Stage2 = crypto:hash(sha, Stage1),
    Res = crypto:hash_final(
	    crypto:hash_update(
	      crypto:hash_update(crypto:hash_init(sha), Salt),
	      Stage2)
	   ),
    bxor_binary(Res, Stage1).

password_sha2(Password, Salt) ->
    PasswordB = <<(iolist_to_binary(Password))/binary>>,
    Stage1 = crypto:hash(sha256, PasswordB),
    Stage2 = crypto:hash(sha256, Stage1),
    Stage3 = crypto:hash(sha256, <<Stage2/binary, (iolist_to_binary(Salt))/binary>>),
    <<Stage1N:256>> = Stage1,
    <<Stage3N:256>> = Stage3,
    <<(Stage1N bxor Stage3N):256>>.


do_send(#state{socket = {SockMod, Sock}}, Packet, Num, LogFun) ->
    p1_mysql:log(LogFun, debug, "p1_mysql_auth send packet ~p: ~p", [Num, Packet]),
    Data = <<(size(Packet)):24/little, Num:8, Packet/binary>>,
    SockMod:send(Sock, Data).
