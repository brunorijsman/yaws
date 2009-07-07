-module(yaws_cgi).
-author('carsten@codimi.de').
-author('brunorijsman@hotmail.com').         %% Added support for FastCGI

%% @@@ remove this
-define(debug, true).

-include("../include/yaws_api.hrl").
-include("yaws_debug.hrl").
-include("../include/yaws.hrl").

-export([call_cgi/5, call_cgi/4, call_cgi/3, call_cgi/2]).
-export([call_fcgi_responder/2, call_fcgi_responder/1]).

-export([cgi_worker/7, fcgi_worker/4]).

%%======================================================================================================================
%% Code which is shared between CGI and FastCGI    
%%======================================================================================================================

-define(ASCII_NEW_LINE, 10).
-define(ASCII_CARRIAGE_RETURN, 13).


handle_clidata(Arg, Worker) ->
    case Arg#arg.clidata of
        undefined ->
            end_of_clidata(Arg, Worker);
        {partial, Data} ->
            send_clidata(Worker, Data),
            {get_more, cgicont, {cgistate, Worker}};
        Data when is_binary(Data) ->
            send_clidata(Worker, Data),
            end_of_clidata(Arg, Worker)
    end.


end_of_clidata(Arg, Worker) ->
    Worker ! {self(), end_of_clidata},
    get_from_worker(Arg, Worker).


send_clidata(Worker, Data) ->
    Worker ! {self(), clidata, Data},
    receive
        {Worker, clidata_receipt} -> ok
    end.


get_from_worker(Arg, Worker) ->
    {Headers, Data} = get_resp(Worker),
    AllResps = lists:map(fun(X)->do_header(Arg, X, Data) end, Headers),
    {ContentResps, Others} = filter2(fun iscontent/1, AllResps),
    {RedirResps, OtherResps} = filter2(fun isredirect/1, Others), 
    case RedirResps of
        [R|_] ->
            Worker ! {self(), no_data},
            OtherResps ++ [R];
        [] ->
            case ContentResps of
                [C={streamcontent, _, _}|_] ->
                    Worker ! {self(), stream_data},
                    OtherResps++[C];
                [C={content, _, _}|_] ->
                    Worker ! {self(), no_data},
                    OtherResps++[C];
                [] ->
                    Worker ! {self(), no_data},
                    OtherResps
            end
    end.


filter2(Pred, Xs) ->
    filter2(Pred, Xs, [], []).

filter2(_Pred, [], Ts, Fs) ->
    {lists:reverse(Ts), lists:reverse(Fs)};
filter2(Pred, [X|Xs], Ts, Fs) ->
    case Pred(X) of
        true ->
            filter2(Pred, Xs, [X|Ts], Fs);
        false ->
            filter2(Pred, Xs, Ts, [X|Fs])
    end.


iscontent({content, _, _}) ->
    true;
iscontent({streamcontent, _, _}) ->
    true;
iscontent(_) ->
    false.


isredirect({status, I}) when is_integer(I) , I >301, I < 304 ->
    true;
isredirect(_) ->
    false.


checkdef(undefined) ->
    "";
checkdef(L) ->
    L.


deep_drop_prefix([], L) ->
    L;
deep_drop_prefix([X|Xs], [X|Ys]) when is_integer(X) ->
    deep_drop_prefix(Xs, Ys);
deep_drop_prefix([X|Xs], Ys) when is_list(X) ->
    deep_drop_prefix(X++Xs, Ys);
deep_drop_prefix(Xs, [Y|Ys]) when is_list(Y) ->
    deep_drop_prefix(Xs, Y++Ys);
deep_drop_prefix(_, _) ->
    false.


get_socket_peername(Socket={sslsocket,_,_}) ->
    {ok, {IP, _Port}}=ssl:peername(Socket),
    inet_parse:ntoa(IP);
get_socket_peername(Socket) ->
    {ok, {IP, _Port}}=inet:peername(Socket),
    inet_parse:ntoa(IP).


get_socket_sockname(Socket={sslsocket,_,_}) ->
    {ok, {IP, _Port}}=ssl:sockname(Socket),
    inet_parse:ntoa(IP);
get_socket_sockname(Socket) ->
    {ok, {IP, _Port}}=inet:sockname(Socket),
    inet_parse:ntoa(IP).


build_env(Arg, Scriptfilename, Pathinfo, ExtraEnv, SC) ->
    H = Arg#arg.headers,
    R = Arg#arg.req,
    case R#http_request.path of
        {abs_path, RequestURI} -> ok;
        _ -> RequestURI = undefined
    end,
    {Maj,Min} = R#http_request.version,
    {Hostname, Hosttail}=lists:splitwith(fun(X)->X /= $: end, 
                                         checkdef(H#headers.host)),
    Hostport = case Hosttail of
                   [$: | P] -> P;
                   [] -> integer_to_list(SC#sconf.port)
               end,
    PeerAddr = get_socket_peername(Arg#arg.clisock),
    LocalAddr = get_socket_sockname(Arg#arg.clisock),

    Scheme = (catch yaws:redirect_scheme(SC)),
    %% Needed by trac, for redirs after POST
    HttpsEnv  = case Scheme of
                    "https://" -> [{"HTTPS", "1"}];
                    _ ->[]
                end,


    %%Scriptname = deep_drop_prefix(Arg#arg.docroot, Arg#arg.fullpath),
    %%SCRIPT_NAME is the path of the script relative to the root of the website.
    %%just dropping docroot from the fullpath does not give the full SCRIPT_NAME 
    %% path if a 'vdir' is involved.
    UriTail = deep_drop_prefix(Arg#arg.docroot, Arg#arg.fullpath),
    case Arg#arg.docroot_mount of
        "/" ->
            %%no arg.docroot_mount means that arg.docroot 
            %% corresponds to the URI-root of the request "/"
            Scriptname = UriTail;
        Vdir ->
            Scriptname = Vdir ++ string:strip(UriTail,left,$/)
    end,        

    Pathinfo2 = checkdef(Pathinfo),
    case Pathinfo2 of
        "" ->
            PathTranslated = "";
        _ ->
            %%determine what physical path the server would map Pathinfo2 
            %%to if it had received just Pathinfo2 in the request.
            PathTranslated = yaws_server:mappath(SC,Arg,Pathinfo2)
    end,


    %%Pass auth info in environment - yes - including password in plain text.
    %%REMOTE_USER always = AUTH_USER
    %%!todo - LOGON_USER - same as AUTH_USER unless some auth filter has mapped 
    %%the user to another username under which to run the request.
    case H#headers.authorization of
        undefined ->
            AuthEnv = [];
        {User, Password, "Basic " ++ Auth64} ->
            AuthEnv = [
                       {"HTTP_AUTHORIZATION", "Basic " ++ Auth64},
                       {"AUTH_TYPE", "Basic"},
                       {"AUTH_USER", User},
                       {"REMOTE_USER", User},
                       {"LOGON_USER", User},
                       {"AUTH_PASSWORD", Password}
                      ];
        {_User, _Password, _OrigString} ->
            %%not attempting to pass through any auth info for 
            %% auth schemes that we don't yet handle
            AuthEnv = []
    end,

    Extra_CGI_Vars = lists:flatmap(fun({Dir, Vars}) ->
					   case lists:prefix(Dir, Scriptname) of
					       true -> Vars;
					       false -> []
					   end
				   end,
				   SC#sconf.extra_cgi_vars),

    %%todo - review. should AuthEnv entries be overridable by ExtraEnv or not?
    %% we should define policy here rather than let through dupes.

    ExtraEnv ++
        HttpsEnv ++
        AuthEnv ++
        lists:filter(
          fun({K, L}) when is_list(L) -> 
                  case lists:keysearch(K, 1, ExtraEnv) of
                      false ->
                          true;
                      _ ->
                          %% we have override in extraenv
                          false
                  end;
             (_) ->
                  false
          end,      
          ([
            {"SERVER_SOFTWARE", "Yaws/"++yaws_generated:version()},
            {"SERVER_NAME", Hostname},
            {"HTTP_HOST", Hostname},
            {"GATEWAY_INTERFACE", "CGI/1.1"},
            {"SERVER_PROTOCOL", "HTTP/" ++ integer_to_list(Maj) ++ 
             "." ++ integer_to_list(Min)},
            {"SERVER_PORT", Hostport},
            {"REQUEST_METHOD", yaws:to_list(R#http_request.method)},
            {"REQUEST_URI", RequestURI},
            {"DOCUMENT_ROOT",         Arg#arg.docroot},
            {"DOCUMENT_ROOT_MOUNT", Arg#arg.docroot_mount},
            {"SCRIPT_FILENAME", Scriptfilename},% For PHP 4.3.2 and higher
                                                % see http://bugs.php.net/bug.php?id=28227
                                                % (Sergei Golovan).
                                                % {"SCRIPT_TRANSLATED", Scriptfilename},   %IIS6+ 
            {"PATH_INFO",                Pathinfo2},
            {"PATH_TRANSLATED",        PathTranslated},  
            %% <JMN_2007-02> 
            %%  CGI/1.1 spec says PATH_TRANSLATED should be NULL or unset 
            %% if PATH_INFO is NULL
            %%  This is in contrast to IIS behaviour - and may break some apps.
            %%  broken apps that expect it to always correspond to path of 
            %% script
            %%  should be modified to use SCRIPT_FILENAME instead - or wrapped.
            %% </JMN_2007-02>
            %% --------------------
            %%  <pre_2007-02_comments>
            %%  This seems not to
            %%  correspond to the
            %%  documentation I have
            %%  read, but it works
            %%  with PHP.
            %% 
            %%  (Not with PHP 4.3.10-16) from
            %%  Debian sarge (Sergei Golovan).
            %%  </pre_2007-02_comments>
            %% ---------------------
            {"SCRIPT_NAME", Scriptname},
            {"REMOTE_ADDR", PeerAddr},
            {"REMOTE_HOST", PeerAddr},  %%  We SHOULD send this
            %%  Resolving DNS not practical for performance reasons 
            %%  - at least on 1st contact from a particular host.
            %%  we could do background lookup so that it's available 
            %% for subsequent invocations,
            %%  but it hardly seems worthwhile. We are permitted by the 
            %% CGI/1.1 spec to substitute REMOTE_ADDR
            {"SERVER_ADDR", LocalAddr},   %% Apache compat
            {"LOCAL_ADDR", LocalAddr},    %% IIS compat
            {"QUERY_STRING", checkdef(Arg#arg.querydata)},
            {"CONTENT_TYPE", H#headers.content_type},
            {"CONTENT_LENGTH", H#headers.content_length},
            {"HTTP_ACCEPT", H#headers.accept},
            {"HTTP_USER_AGENT", H#headers.user_agent},
            {"HTTP_REFERER", H#headers.referer},
            {"HTTP_IF_MODIFIED_SINCE", H#headers.if_modified_since},
            {"HTTP_IF_MATCH", H#headers.if_match},
            {"HTTP_IF_NONE_MATCH", H#headers.if_none_match},
            {"HTTP_IF_UNMODIFIED_SINCE", H#headers.if_unmodified_since},
            {"HTTP_COOKIE", flatten_val(make_cookie_val(H#headers.cookie))}
           ]++lists:map(fun({http_header,_,Var,_,Val})->{tohttp(Var),Val} end,
                        H#headers.other)
          )) ++
	Extra_CGI_Vars.

tohttp(X) ->
    "HTTP_"++lists:map(fun tohttp_c/1, yaws:to_list(X)).


tohttp_c($-) ->
    $_;

tohttp_c(C) when C >= $a , C =< $z ->
    C - $a + $A;

tohttp_c(C) ->
    C.


make_cookie_val([]) ->
    undefined;
make_cookie_val([C]) ->
    C;
make_cookie_val([C|CS]) ->
    [make_cookie_val(CS), $; | C].


%% Seems not to be necessary, but open_port documentation says that
%% value has to be a string.

flatten_val(L) when is_list(L) ->
    lists:flatten(L);
flatten_val(X) ->
    X.


notslash($/) ->
    false;
notslash(_) ->
    true.


pathof(F) ->
    case lists:dropwhile(fun notslash/1, lists:reverse(F)) of
        "/" ->
            "/";
        [$/ | Tail] -> lists:reverse(Tail)
    end.


exeof(F) ->
    [$\., $/|lists:reverse(lists:takewhile(fun notslash/1, lists:reverse(F)))].


%% We almost always generate stream content.
%% Actually, we could do away with `content' altogether.

do_header(_Arg, "Content-type: "++CT, {partial_data, Data}) ->
    {streamcontent, CT, Data};
do_header(_Arg, "Content-type: "++CT, {all_data, Data}) ->
    {content, CT, Data};
do_header(_Arg, "Content-Type: "++CT, {partial_data, Data}) ->
    {streamcontent, CT, Data};
do_header(_Arg, "Content-Type: "++CT, {all_data, Data}) ->
    {content, CT, Data};
do_header(_Arg, "Status: "++[N1,N2,N3|_], _) ->
    {status, list_to_integer([N1,N2,N3])};
do_header(_Arg, "HTTP/1."++[_,_,N1,N2,N3|_], _) ->
    {status, list_to_integer([N1,N2,N3])};
do_header(_Arg, Line, _) ->
    {header, Line}.   


get_resp(Worker) ->
    get_resp([], Worker).

get_resp(Hs, Worker) ->
    receive
        {Worker, header, H} ->
            ?Debug("~p~n", [{Worker, header, H}]),
            get_resp([H|Hs], Worker);
        {Worker, all_data, Data} ->
            ?Debug("~p~n", [{Worker, all_data, Data}]),
            {Hs, {all_data, Data}};
        {Worker, partial_data, Data} ->
            ?Debug("~p~n", [{Worker, partial_data, binary_to_list(Data)}]),
            {Hs, {partial_data, Data}};
        {Worker, failure, _} ->
            {[], undef};
        _Other ->
            ?Debug("~p~n", [_Other]),
            get_resp(Hs, Worker)
    end.


worker_fail(ParentPid, Failure) ->
    ParentPid ! {failure, Failure},
    exit(Failure).


worker_fail_if(Condition, ParentPid, Failure) ->
    if 
        Condition ->
            worker_fail(ParentPid, Failure);
        true ->
            ok
    end.


get_opt(Key, List, Default) ->
    case lists:keysearch(Key, 1, List) of
        {value, {_Key, Val}} -> Val;
        _ -> Default
    end.


%%======================================================================================================================
%% Code which is specific to CGI    
%%======================================================================================================================

%%  TO DO:  Handle failure and timeouts.

%%  call_cgi calls the script `Scriptfilename' (full path).
%%  If `Exefilename' is given, it is the executable to handle this, 
%%  otherwise `Scriptfilame' is assumed to be executable itself.
%%  
%%  Corresponding to a URI of
%%     `http://somehost/some/dir/script.cgi/path/info', 
%%  `Pathinfo' should be set to `/path/info'.

%%  These functions can be used from a `.yaws' file.
%%  Note however, that they usually generate stream content.

call_cgi(Arg, Scriptfilename) ->                                     
    call_cgi(Arg, undefined, Scriptfilename, undefined, []).

call_cgi(Arg, Exefilename, Scriptfilename) ->
    call_cgi(Arg, Exefilename, Scriptfilename, undefined, []).

call_cgi(Arg, Exefilename, Scriptfilename, Pathinfo) ->
    call_cgi(Arg, Exefilename, Scriptfilename, Pathinfo, []).

call_cgi(Arg, Exefilename, Scriptfilename, Pathinfo, ExtraEnv) ->
    case Arg#arg.state of
        {cgistate, Worker} ->
            case Arg#arg.cont of
                cgicont -> 
                    handle_clidata(Arg, Worker);
                undefined ->
                    ?Debug("Error while reading clidata: ~p~n", 
                           [Arg#arg.clidata]),
                    %%  Error, what to do?
                    exit(normal)
            end;
        _ ->
            Worker = cgi_start_worker(Arg, Exefilename, Scriptfilename, 
                                      Pathinfo, ExtraEnv, get(sc)),
            handle_clidata(Arg, Worker)
    end.


cgi_start_worker(Arg, Exefilename, Scriptfilename, Pathinfo, ExtraEnv, SC) ->
    ExeFN = case Exefilename of 
                undefined -> exeof(Scriptfilename);
                "" -> exeof(Scriptfilename);
                FN -> FN
            end,
    PI = case Pathinfo of
             undefined -> Arg#arg.pathinfo;
             OK -> OK
         end,
    Worker = proc_lib:spawn(?MODULE, cgi_worker, 
                            [self(), Arg, ExeFN, Scriptfilename, PI, ExtraEnv, SC]),
    Worker.



cgi_worker(Parent, Arg, Exefilename, Scriptfilename, Pathinfo, ExtraEnv,SC) ->
    Env = build_env(Arg, Scriptfilename, Pathinfo, ExtraEnv,SC),
    ?Debug("~p~n", [Env]),
    CGIPort = open_port({spawn, Exefilename},
                        [{env, Env}, 
                         {cd, pathof(Scriptfilename)},
                         exit_status,
                         binary]),
    cgi_pass_through_clidata(Parent, CGIPort),
    cgi_do_work(Parent, Arg, CGIPort).


cgi_pass_through_clidata(Parent, CGIPort) ->
    receive
        {Parent, clidata, Clidata} ->
            ?Debug("Got clidata ~p~n", [binary_to_list(Clidata)]),
            Parent ! {self(), clidata_receipt},
            CGIPort ! {self(), {command, Clidata}},
            cgi_pass_through_clidata(Parent, CGIPort);
        {Parent, end_of_clidata} ->
            ?Debug("End of clidata~n", []),
            ok
    end.


cgi_do_work(Parent, Arg, Port) ->
    cgi_header_loop(Parent, Arg, {start, Port}).


cgi_header_loop(Parent, Arg, S) ->
    Line = cgi_get_line(S),
    ?Debug("Line = ~p~n", [Line]),
    case Line of
        {failure, F} ->
            Parent ! {self(), failure, F};
        {[], T} ->
            case T of
                {middle, Data, Port} ->
                    Parent ! {self(), partial_data, Data},
                    receive
                        {Parent, stream_data} ->
                            cgi_data_loop(Arg#arg.pid, Port);
                        {Parent, no_data} ->
                            ok
                    end;
                {ending, Data, _} ->
                    Parent ! {self(), all_data, Data},
                    receive
                        {Parent, stream_data} ->
                            yaws_api:stream_chunk_end(Arg#arg.pid);
                        {Parent, no_data} ->
                            ok
                    end
            end;
        {H, T} ->
            Parent ! {self(), header, H},
            cgi_header_loop(Parent, Arg, T)
    end.


cgi_data_loop(Pid, Port) ->
    receive
        {Port, {data,Data}} ->
            ?Debug("~p~n", [{data, binary_to_list(Data)}]),
            yaws_api:stream_chunk_deliver_blocking(Pid, Data),
            cgi_data_loop(Pid, Port);
        {Port, {exit_status, _Status}} ->
            ?Debug("~p~n", [{exit_status, _Status}]),            
            yaws_api:stream_chunk_end(Pid);
        _Other ->
            ?Debug("~p~n", [_Other]),
            cgi_data_loop(Pid, Port)
    end.



cgi_get_line({start, Port}) ->
    receive
        {Port, {data,Data}} ->
            cgi_get_line([], {middle, Data, Port});
        {Port, {exit_status, 0}} ->
            ?Debug("~p~n", [{exit_status, 0}]),
            cgi_get_line([], {ending, <<>>, Port});
        {Port, {exit_status, Status}} when Status /=0 ->
            ?Debug("~p~n", [{exit_status, Status}]),
            {failure, {exit_status, Status}};
        _Other ->
            ?Debug("~p~n", [_Other]),            
            cgi_get_line({start, Port})
    end;
cgi_get_line(State) ->
    cgi_get_line([], State).


cgi_get_line(Acc, {S, <<?ASCII_NEW_LINE, Tail/binary>>, Port}) ->
    {lists:reverse(Acc), {S, Tail, Port}};
cgi_get_line(Acc, {S, <<?ASCII_CARRIAGE_RETURN, ?ASCII_NEW_LINE, Tail/binary>>, Port}) ->
    {lists:reverse(Acc), {S, Tail, Port}};
cgi_get_line(Acc, {middle, <<>>, Port}) ->
    cgi_get_line(Acc, cgi_add_resp(<<>>, Port));
cgi_get_line(Acc, {middle, <<?ASCII_CARRIAGE_RETURN>>, Port}) ->          % We SHOULD test for CRLF.
    cgi_get_line(Acc, cgi_add_resp(<<?ASCII_CARRIAGE_RETURN>>, Port));    % Would be easier without.
cgi_get_line(Acc, {ending, <<>>, Port}) ->
    {lists:reverse(Acc), {ending, <<>>, Port}};
cgi_get_line(Acc, {S, <<C, Tail/binary>>, Port}) ->
    cgi_get_line([C|Acc], {S, Tail, Port}).


cgi_add_resp(Bin, Port) ->
    receive
        {Port, {data,Data}} ->
            {middle, <<Bin/binary, Data/binary>>, Port};
        {Port, {exit_status, _Status}} ->
            ?Debug("~p~n", [{exit_status, _Status}]),            
            {ending, Bin, Port};
        _Other ->
            ?Debug("~p~n", [_Other]),
            cgi_add_resp(Bin, Port)
    end.


%%======================================================================================================================
%% Code which is specific to FastCGI    
%%======================================================================================================================

-define(FCGI_VERSION_1, 1).

-define(FCGI_TYPE_BEGIN_REQUEST, 1).
-define(FCGI_TYPE_ABORT_REQUEST, 2).
-define(FCGI_TYPE_END_REQUEST, 3).
-define(FCGI_TYPE_PARAMS, 4).
-define(FCGI_TYPE_STDIN, 5).
-define(FCGI_TYPE_STDOUT, 6).
-define(FCGI_TYPE_STDERR, 7).
-define(FCGI_TYPE_DATA, 8).
-define(FCGI_TYPE_GET_VALUES, 9).
-define(FCGI_TYPE_GET_VALUES_RESULT, 10).
-define(FCGI_TYPE_UNKNOWN_TYPE, 11).

% The FCGI implementation does not support handling concurrent requests over a connection; it creates a separate 
% connection for each request. Hence, all application records have the same request-id, namely 1.
%
-define(FCGI_REQUEST_ID_MANAGEMENT, 0).
-define(FCGI_REQUEST_ID_APPLICATION, 1).

-define(FCGI_DONT_KEEP_CONN, 0).
-define(FCGI_KEEP_CONN, 1).

-define(FCGI_ROLE_RESPONDER, 1).
-define(FCGI_ROLE_AUTHORIZER, 2).
-define(FCGI_ROLE_FILTER, 3).

-define(FCGI_STATUS_REQUEST_COMPLETE, 0).
-define(FCGI_STATUS_CANT_MPX_CONN, 1).
-define(FCGI_STATUS_OVERLOADED, 2).
-define(FCGI_STATUS_UNKNOWN_ROLE, 3).

%% @@TODO: Make this a total timeout
%%
-define(FCGI_CONFIG_CONNECT_TIMEOUT_MSECS, 1000).
-define(FCGI_CONFIG_READ_TIMEOUT_MSECS, 1000).

% We currently always delegate close authority to the application. We might want to add a configuration option for this.
%
-define(FCGI_CONFIG_KEEP_CONNECTION, false).

%% @@TODO: Make all of the following things configurable in yaws.conf
%% @@TODO: implement timeout
%% @@TODO: add flag for logging stderr output
-record(fcgi_conf, {
            app_server_host,            % The hostname or IP address of the application server
            app_server_port,            % The TCP port number of the application server
            path_info,                  % The path info
            extra_env,                  % Any extra environment variables to be passed to the application server
            request_timeout,            % Total amount of time (in milliseconds) allowed for a request to be completed
            trace_protocol              % If true, log info messages for sent and received FastCGI messages
        }).

call_fcgi_responder(Arg) ->
    call_fcgi_responder(Arg, []).

call_fcgi_responder(Arg, Options) ->
    case Arg#arg.state of
        {cgistate, Worker} ->
            case Arg#arg.cont of
                cgicont -> 
                    ?Debug("call_fcgi_responder: continuation~n", []),
                    handle_clidata(Arg, Worker)
            end;
        _ ->
            ServerConf = get(sc),
            AppServerHost = get_opt(app_server_host, Options, ServerConf#sconf.fcgi_app_server_host),
            AppServerPort = get_opt(app_server_port, Options, ServerConf#sconf.fcgi_app_server_port),
            PathInfo = get_opt(path_info, Options, Arg#arg.pathinfo),
            ExtraEnv = get_opt(extra_env, Options, []),
            RequestTimeout = get_opt(request_timeout, Options, 5000),
            TraceProtocol = get_opt(trace_protocol, Options, ?sc_fcgi_trace_protocol(ServerConf)),
            ?Debug("call_fcgi_responder:~n"
                   "  AppServerHost = ~p~n"
                   "  AppServerPort = ~p~n"
                   "  PathInfo = ~p~n"
                   "  ExtraEnv = ~p~n"
                   "  RequestTimeout = ~p~n"
                   "  TraceProtocol = ~p~n", 
                   [AppServerHost, AppServerPort, PathInfo, ExtraEnv, RequestTimeout, TraceProtocol]),
            FcgiConf = #fcgi_conf{
                app_server_host = AppServerHost,
                app_server_port = AppServerPort,
                path_info = PathInfo,
                extra_env = ExtraEnv,
                request_timeout = RequestTimeout,
                trace_protocol = TraceProtocol              
            },
            Worker = fcgi_start_worker(Arg, ServerConf, FcgiConf),
            handle_clidata(Arg, Worker)
    end.


fcgi_start_worker(Arg, ServerConf, FcgiConf) ->
    proc_lib:spawn(?MODULE, fcgi_worker, [self(), Arg, ServerConf, FcgiConf]).


fcgi_worker(ParentPid, Arg, ServerConf, FcgiConf) ->
    ScriptFileName = "",
    PathInfo = FcgiConf#fcgi_conf.path_info,
    ExtraEnv = FcgiConf#fcgi_conf.extra_env,
    Env = build_env(Arg, ScriptFileName, PathInfo, ExtraEnv, ServerConf),
    Trace = FcgiConf#fcgi_conf.trace_protocol,
    Socket = fcgi_connect_to_application_server(ParentPid, Arg, ServerConf),
    fcgi_send_begin_request(ParentPid, Socket, Trace, ?FCGI_ROLE_RESPONDER, ?FCGI_CONFIG_KEEP_CONNECTION),
    fcgi_send_params(ParentPid, Socket, Trace, Env),
    fcgi_send_params(ParentPid, Socket, Trace, []),
    fcgi_pass_through_client_data(ParentPid, Socket, Trace),
    fcgi_header_loop(ParentPid, Socket, Trace, Arg),
    gen_tcp:close(Socket),     % If keep connection is false, application should close connection, but don't rely on it.
    ok.


fcgi_pass_through_client_data(ParentPid, Socket, Trace) ->
    receive
        {ParentPid, clidata, ClientData} ->
            ParentPid ! {self(), clidata_receipt},
            fcgi_send_stdin(ParentPid, Socket, Trace, ClientData),
            fcgi_pass_through_client_data(ParentPid, Socket, Trace);
        {ParentPid, end_of_clidata} ->
            fcgi_send_stdin(ParentPid, Socket, Trace, <<>>)
    end.


fcgi_choose_application_server(ParentPid, _Arg, ServerConf) ->
    Host = case ServerConf#sconf.fcgi_app_server_host of
        undefined ->
            worker_fail(ParentPid, fcgi_app_server_host_not_configured);
        ValidHost ->
            ValidHost
    end,
    Port = case ServerConf#sconf.fcgi_app_server_port of
        undefined ->
            worker_fail(ParentPid, fcgi_app_server_port_not_configured);
        ValidPort ->
            ValidPort
    end,
    {Host, Port}.


fcgi_connect_to_application_server(ParentPid, Arg, ServerConf) ->
    {Host, Port} = fcgi_choose_application_server(ParentPid, Arg, ServerConf),
    Options = [binary, {packet, 0}, {active, false}],
    case gen_tcp:connect(Host, Port, Options, ?FCGI_CONFIG_CONNECT_TIMEOUT_MSECS) of
        {error, Reason2} ->
            worker_fail(ParentPid, {connect_to_application_server_failed, Reason2});
        {ok, Socket} ->
            Socket
    end.


fcgi_send_begin_request(ParentPid, Socket, Trace, Role, KeepConnection) ->
    Flags = case KeepConnection of
        true -> ?FCGI_KEEP_CONN;
        false -> ?FCGI_DONT_KEEP_CONN
    end,
    fcgi_send_record(ParentPid, Socket, Trace, ?FCGI_TYPE_BEGIN_REQUEST, ?FCGI_REQUEST_ID_APPLICATION, 
                     <<Role:16, Flags:8, 0:40>>).


fcgi_send_params(ParentPid, Socket, Trace, NameValueList) -> 
    fcgi_send_record(ParentPid, Socket, Trace, ?FCGI_TYPE_PARAMS, ?FCGI_REQUEST_ID_APPLICATION, NameValueList).


fcgi_send_stdin(ParentPid, Socket, Trace, Data) ->
    fcgi_send_record(ParentPid, Socket, Trace, ?FCGI_TYPE_STDIN, ?FCGI_REQUEST_ID_APPLICATION, Data).


%% TODO: Not used yet
%% fcgi_send_data(ParentPid, Socket, Data) ->
%%     fcgi_send_record(ParentPid, Socket, ?FCGI_TYPE_DATA, ?FCGI_REQUEST_ID_APPLICATION, Data).


%% TODO: Not used yet
%% fcgi_send_abort_request(ParentPid, Socket) ->
%%     fcgi_send_record(ParentPid, Socket, ?FCGI_TYPE_ABORT_REQUEST, ?FCGI_REQUEST_ID_APPLICATION, <<>>).


fcgi_type_name(?FCGI_TYPE_BEGIN_REQUEST) -> "begin-request";
fcgi_type_name(?FCGI_TYPE_ABORT_REQUEST) -> "abort-request";
fcgi_type_name(?FCGI_TYPE_END_REQUEST) -> "end-request";
fcgi_type_name(?FCGI_TYPE_PARAMS) -> "params";
fcgi_type_name(?FCGI_TYPE_STDIN) -> "stdin";
fcgi_type_name(?FCGI_TYPE_STDOUT) -> "stdout";
fcgi_type_name(?FCGI_TYPE_STDERR) -> "stderr";
fcgi_type_name(?FCGI_TYPE_DATA) -> "data";
fcgi_type_name(?FCGI_TYPE_GET_VALUES) -> "get_values";
fcgi_type_name(?FCGI_TYPE_GET_VALUES_RESULT) -> "get_values_result";
fcgi_type_name(?FCGI_TYPE_UNKNOWN_TYPE) -> "unknown-type";
fcgi_type_name(_) -> "?".

fcgi_data_to_string(Data) ->
    fcgi_data_to_string("", 0, "", "", Data).

fcgi_data_to_string(LinesStr, Count, CharStr, HexStr, <<>>) ->
    if
        Count == 0 ->
            LinesStr;
        true ->
            Padding = lists:duplicate(16 - Count, $ ),
            LinesStr ++ "\n    " ++ CharStr ++ Padding ++ "  " ++ HexStr
    end;
fcgi_data_to_string(LinesStr, Count, CharStr, HexStr, <<Byte:8, MoreData/binary>>) ->
    Char = if 
        (Byte >= $!) and (Byte =< $~) ->
            Byte;
        true ->
            $.
    end,
    Hex = io_lib:format("~2.16.0b ", [Byte]),
    if
        Count == 16 ->
            fcgi_data_to_string(LinesStr ++ "\n    " ++ CharStr ++ "  " ++ HexStr, 1, [Char], Hex, MoreData);
        true ->
            fcgi_data_to_string(LinesStr, Count + 1, CharStr ++ [Char], HexStr ++ Hex, MoreData)
    end.


fcgi_trace_protocol(Trace, Action, Version, Type, RequestId, ContentLength, PaddingLength, Reserved, ContentData, 
                    PaddingData) ->
    if
        Trace -> 
            error_logger:info_msg(
                "~s FastCGI record:~n"
                "  version = ~p~n"
                "  type = ~p (~s)~n"
                "  request-id = ~p~n"
                "  content-length = ~p~n"
                "  padding-length = ~p~n"
                "  reserved = ~p~n"
                "  content-data = ~s~n"
                "  padding-data = ~s~n",
                [Action,
                 Version, 
                 Type, fcgi_type_name(Type), 
                 RequestId, 
                 ContentLength, 
                 PaddingLength, 
                 Reserved, 
                 fcgi_data_to_string(ContentData), 
                 fcgi_data_to_string(PaddingData)]);
        true -> 
            ok
    end.
    
    
fcgi_send_record(ParentPid, Socket, Trace, Type, RequestId, NameValueList) ->
    EncodedRecord = fcgi_encode_record(Trace, Type, RequestId, NameValueList),
    case gen_tcp:send(Socket, EncodedRecord) of
        {error, Reason} ->
            worker_fail(ParentPid, {send_to_application_server_failed, Reason});
        ok ->
            ok
    end.


fcgi_encode_record(Trace, Type, RequestId, NameValueList) 
  when is_list(NameValueList) ->
    fcgi_encode_record(Trace, Type, RequestId, fcgi_encode_name_value_list(NameValueList));
    
fcgi_encode_record(Trace, Type, RequestId, ContentData) 
  when is_binary(ContentData) ->
    Version = 1,
    ContentLength = size(ContentData),
    PaddingLength = if                              % Add padding bytes (if needed) to content bytes to make
        ContentLength rem 8 == 0 ->                 % content plus padding a multiple of 8 bytes.
            0;
        true ->
            8 - (ContentLength rem 8)
    end,
    PaddingData = <<0:(PaddingLength * 8)>>,
    Reserved = 0,
    fcgi_trace_protocol(Trace, "Send", Version, Type, RequestId, ContentLength, PaddingLength, Reserved, ContentData, 
                        PaddingData),
    <<Version:8,
      Type:8,
      RequestId:16,
      ContentLength:16,
      PaddingLength:8,
      Reserved:8,
      ContentData/binary,
      PaddingData/binary>>.


fcgi_encode_name_value_list(_NameValueList = []) ->
    <<>>;
fcgi_encode_name_value_list(_NameValueList = [{Name, Value} | Tail]) -> 
    <<(fcgi_encode_name_value(Name,Value))/binary, (fcgi_encode_name_value_list(Tail))/binary>>.


fcgi_encode_name_value(Name, _Value = undefined) ->
    fcgi_encode_name_value(Name, "");
fcgi_encode_name_value(Name, Value) when is_list(Name) and is_list(Value) ->
    NameSize = length(Name),
    NameSizeData = if
        NameSize < 128 ->                         % If name size is < 128, encode it as one byte with the high bit 
            <<NameSize:8>>;                       % clear. If the name size >= 128, encoded it as 4 bytes with the high
        true ->                                   % bit set
            <<(NameSize bor 16#80000000):32>>
    end,
    % Same encoding for the value size.
    ValueSize = length(Value),
    ValueSizeData = if
        ValueSize < 128 -> 
            <<ValueSize:8>>; 
        true -> 
            <<(ValueSize bor 16#80000000):32>>
    end,
    <<NameSizeData/binary,
      ValueSizeData/binary,
      (list_to_binary(Name))/binary,
      (list_to_binary(Value))/binary>>.


fcgi_header_loop(ParentPid, Socket, Trace, Arg) ->
    fcgi_header_loop(ParentPid, Socket, Trace, Arg, start).

fcgi_header_loop(ParentPid, Socket, Trace, Arg, GatherState) ->
    Line = fcgi_get_line(ParentPid, Socket, Trace, GatherState),
    case Line of
        {failure, Failure} ->                           %% TODO: need this?
            ParentPid ! {self(), failure, Failure};
        {_EmptyLine = [], NewGatherState} ->
            case NewGatherState of
                {middle, Data} ->
                    ParentPid ! {self(), partial_data, Data},
                    receive
                        {ParentPid, stream_data} ->
                            fcgi_data_loop(ParentPid, Socket, Trace, Arg#arg.pid);
                        {ParentPid, no_data} ->
                            ok
                    end;
                {ending, Data} ->
                    ParentPid ! {self(), all_data, Data},
                    receive
                        {ParentPid, stream_data} ->
                            yaws_api:stream_chunk_end(Arg#arg.pid);
                        {ParentPid, no_data} ->
                            ok
                    end
            end;
        {Header, NewGatherState} ->
            ParentPid ! {self(), header, Header},
            fcgi_header_loop(ParentPid, Socket, Trace, Arg, NewGatherState)
    end.


fcgi_get_line(ParentPid, Socket, Trace, start) ->
    case fcgi_get_output(ParentPid, Socket, Trace) of 
        {data, Data} ->
            fcgi_get_line(ParentPid, Socket, Trace, [], {middle, Data});
        {exit_status, 0} ->
            fcgi_get_line(ParentPid, Socket, Trace, [], {ending, <<>>});
        {exit_status, Status} when Status /=0 ->
            {failure, {exit_status, Status}}
    end;
fcgi_get_line(ParentPid, Socket, Trace, GatherState) ->
    fcgi_get_line(ParentPid, Socket, Trace, [], GatherState).

fcgi_get_line(_ParentPid, _Socket, _Trace, Acc, {State, <<?ASCII_NEW_LINE, Tail/binary>>}) ->
    {lists:reverse(Acc), {State, Tail}};
fcgi_get_line(_ParentPid, _Socket, _Trace, Acc, {State, <<?ASCII_CARRIAGE_RETURN, ?ASCII_NEW_LINE, Tail/binary>>}) ->
    {lists:reverse(Acc), {State, Tail}};
fcgi_get_line(ParentPid, Socket, Trace, Acc, {middle, <<>>}) ->
    fcgi_get_line(ParentPid, Socket, Trace, Acc, fcgi_add_resp(ParentPid, Socket, Trace, <<>>));
fcgi_get_line(ParentPid, Socket, Trace, Acc, {middle, <<?ASCII_CARRIAGE_RETURN>>}) ->
    fcgi_get_line(ParentPid, Socket, Trace, Acc, fcgi_add_resp(ParentPid, Socket, Trace, <<?ASCII_CARRIAGE_RETURN>>));
fcgi_get_line(_ParentPid, _Socket, _Trace, Acc, {ending, <<>>}) ->
    {lists:reverse(Acc), {ending, <<>>}};
fcgi_get_line(ParentPid, Socket, Trace, Acc, {State, <<Char, Tail/binary>>}) ->
    fcgi_get_line(ParentPid, Socket, Trace, [Char | Acc], {State, Tail}).


fcgi_add_resp(ParentPid, Socket, Trace, OldData) ->
    case fcgi_get_output(ParentPid, Socket, Trace) of 
        {data, NewData} ->
            {middle, <<OldData/binary, NewData/binary>>};
        {exit_status, _Status} ->
            {ending, OldData}
    end.


fcgi_data_loop(ParentPid, Socket, Trace, StreamToPid) ->
    case fcgi_get_output(ParentPid, Socket, Trace) of 
        {data, Data} ->
            yaws_api:stream_chunk_deliver_blocking(StreamToPid, Data),
            fcgi_data_loop(ParentPid, Socket, Trace, StreamToPid);
        {exit_status, _Status} ->
            yaws_api:stream_chunk_end(StreamToPid)
    end.


fcgi_get_output(ParentPid, Socket, Trace) ->
    {Type, ContentData} = fcgi_receive_record(ParentPid, Socket, Trace),
    case Type of
        ?FCGI_TYPE_END_REQUEST ->
            %% @@TODO: handle non-success prot status
            <<AppStatus:32, ProtStatus:8, _Reserved:24>> = ContentData,
            worker_fail_if(ParentPid, ProtStatus < ?FCGI_STATUS_REQUEST_COMPLETE, 
                           {received_unknown_protocol_status, ProtStatus}),
            worker_fail_if(ProtStatus > ?FCGI_STATUS_UNKNOWN_ROLE, ParentPid, 
                           {received_unknown_protocol_status, ProtStatus}),
            {exit_status, AppStatus};
        ?FCGI_TYPE_STDOUT ->
            {data, ContentData};
        ?FCGI_TYPE_STDERR ->
            %% @@TODO: send message for stderr
            fcgi_get_output(ParentPid, Socket, Trace);
        ?FCGI_TYPE_UNKNOWN_TYPE ->
            <<UnknownType:8, _Reserved:56>> = ContentData,
            worker_fail(ParentPid, {application_did_not_understand_record_type_we_sent, UnknownType});
        OtherType ->
            worker_fail(ParentPid, {received_unknown_record_type, OtherType})
    end.


fcgi_receive_record(ParentPid, Socket, Trace) ->
    {ok, Header} = fcgi_receive_binary(ParentPid, Socket, 8, ?FCGI_CONFIG_READ_TIMEOUT_MSECS),
    <<Version:8, Type:8, RequestId:16, ContentLength:16, PaddingLength:8, Reserved:8>> = Header, 
    worker_fail_if(Version /= 1, ParentPid, {received_unsupported_version, Version}),
    case Type of
        ?FCGI_TYPE_END_REQUEST ->
            worker_fail_if(ParentPid, RequestId /= ?FCGI_REQUEST_ID_APPLICATION, {unexpected_request_id, RequestId}),
            worker_fail_if(ParentPid, ContentLength /= 8, {incorrect_content_length_for_end_request, ContentLength}),
            ok;
        ?FCGI_TYPE_STDOUT ->
            worker_fail_if(ParentPid, RequestId /= ?FCGI_REQUEST_ID_APPLICATION, {unexpected_request_id, RequestId}),
            ok;
        ?FCGI_TYPE_STDERR ->
            worker_fail_if(ParentPid, RequestId /= ?FCGI_REQUEST_ID_APPLICATION, {unexpected_request_id, RequestId}),
            ok;
        ?FCGI_TYPE_UNKNOWN_TYPE ->
            worker_fail_if(ParentPid, RequestId /= ?FCGI_REQUEST_ID_MANAGEMENT, {unexpected_request_id, RequestId}),
            worker_fail_if(ParentPid, ContentLength /= 8, {incorrect_content_length_for_unknown_type, ContentLength}),
            ok;
        OtherType ->
            throw({received_unexpected_type, OtherType})
    end,
    case fcgi_receive_binary(ParentPid, Socket, ContentLength, ?FCGI_CONFIG_READ_TIMEOUT_MSECS) of
        {error, Reason} ->
            worker_fail(ParentPid, {unable_to_read_content_data, Reason});
        {ok, ContentData} ->
            case fcgi_receive_binary(ParentPid, Socket, PaddingLength, ?FCGI_CONFIG_READ_TIMEOUT_MSECS) of
                {error, Reason} ->
                    worker_fail(ParentPid, {unable_to_read_record_padding_data, Reason});
                {ok, PaddingData} ->
                    fcgi_trace_protocol(Trace, "Receive", Version, Type, RequestId, ContentLength, PaddingLength, 
                                        Reserved, ContentData, PaddingData),
                    {Type, ContentData}                            
            end
    end.


fcgi_receive_binary(_ParentPid, _Socket, Length, _Timeout) when Length == 0 ->
    {ok, <<>>};
fcgi_receive_binary(ParentPid, Socket, Length, Timeout) ->
    case gen_tcp:recv(Socket, Length, Timeout) of
        {error, Reason} ->
            worker_fail(ParentPid, {send_to_application_server_failed, Reason});
        {ok, Data} ->
            {ok, Data}
    end.
