-module(yaws_cgi).
-author('carsten@codimi.de').

%% @@@ remove this
-define(debug, true).

-include("../include/yaws_api.hrl").
-include("yaws_debug.hrl").
-include("../include/yaws.hrl").

-export([call_cgi/5, call_cgi/4, call_cgi/3, call_cgi/2]).

-export([cgi_worker/7, fcgi_worker/7]).

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

%% @@TODO: Make the following things configurable:
%%
-define(FCGI_CONFIG_APPLICATION_SERVER_NAME, "localhost").
-define(FCGI_CONFIG_APPLICATION_SERVER_PORT, 9999).
-define(FCGI_CONFIG_CONNECT_TIMEOUT_MSECS, 1000).
-define(FCGI_CONFIG_READ_TIMEOUT_MSECS, 1000).             %% @@@TODO: distinction between first read and additional reads
-define(FCGI_CONFIG_KEEP_CONNECTION, true).

-define(HTML_STATUS_INTERNAL_SERVER_ERROR, 500).           %% @@@TODO: Am I using this? 

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
            Worker = start_worker(Arg, Exefilename, Scriptfilename, 
                                  Pathinfo, ExtraEnv, get(sc)),
            handle_clidata(Arg, Worker)
    end.

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


start_worker(Arg, Exefilename, Scriptfilename, Pathinfo, ExtraEnv, SC) ->
    ExeFN = case Exefilename of 
                undefined -> exeof(Scriptfilename);
                "" -> exeof(Scriptfilename);
                FN -> FN
            end,
    PI = case Pathinfo of
             undefined -> Arg#arg.pathinfo;
             OK -> OK
         end,
%% @@    
%%     Worker = proc_lib:spawn(?MODULE, cgi_worker, 
%%                             [self(), Arg, ExeFN, Scriptfilename, PI, ExtraEnv, SC]),
    Worker = proc_lib:spawn(?MODULE, fcgi_worker, 
                            [self(), Arg, ExeFN, Scriptfilename, PI, ExtraEnv, SC]),
    Worker.


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


cgi_env(Arg, Scriptfilename, Pathinfo, ExtraEnv, SC) ->
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

%% JMN - apparently redundant. host/1 was being used in cgi_env/5 when 
%% Hostname had already been split out of Host. 
%% %%  Get Host part from a host string that can contain host or host:port
%% host(Host) ->
%%    case string:tokens(Host, ":") of
%%        [Hostname, _Port] -> Hostname;
%%        [Hostname]       -> Hostname;
%%        _Other           -> Host
%%    end.


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


cgi_worker(Parent, Arg, Exefilename, Scriptfilename, Pathinfo, ExtraEnv,SC) ->
    Env = cgi_env(Arg, Scriptfilename, Pathinfo, ExtraEnv,SC),
    ?Debug("~p~n", [Env]),
    CGIPort = open_port({spawn, Exefilename},
                        [{env, Env}, 
                         {cd, pathof(Scriptfilename)},
                         exit_status,
                         binary]),
    pass_through_clidata(Parent, CGIPort),
    do_work(Parent, Arg, CGIPort).



pass_through_clidata(Parent, CGIPort) ->
    receive
        {Parent, clidata, Clidata} ->
            ?Debug("Got clidata ~p~n", [binary_to_list(Clidata)]),
            Parent ! {self(), clidata_receipt},
            CGIPort ! {self(), {command, Clidata}},
            pass_through_clidata(Parent, CGIPort);
        {Parent, end_of_clidata} ->
            ?Debug("End of clidata~n", []),
            ok
    end.


do_work(Parent, Arg, Port) ->
    header_loop(Parent, Arg, {start, Port}).

header_loop(Parent, Arg, S) ->
    Line = get_line(S),
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
                            data_loop(Arg#arg.pid, Port);
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
            header_loop(Parent, Arg, T)
    end.


data_loop(Pid, Port) ->
    receive
        {Port, {data,Data}} ->
            ?Debug("~p~n", [{data, binary_to_list(Data)}]),
            yaws_api:stream_chunk_deliver_blocking(Pid, Data),
            data_loop(Pid, Port);
        {Port, {exit_status, _Status}} ->
            ?Debug("~p~n", [{exit_status, _Status}]),            
            yaws_api:stream_chunk_end(Pid);
        _Other ->
            ?Debug("~p~n", [_Other]),
            data_loop(Pid, Port)
    end.



get_line({start, Port}) ->
    receive
        {Port, {data,Data}} ->
            get_line([], {middle, Data, Port});
        {Port, {exit_status, 0}} ->
            ?Debug("~p~n", [{exit_status, 0}]),
            get_line([], {ending, <<>>, Port});
        {Port, {exit_status, Status}} when Status /=0 ->
            ?Debug("~p~n", [{exit_status, Status}]),
            {failure, {exit_status, Status}};
        _Other ->
            ?Debug("~p~n", [_Other]),            
            get_line({start, Port})
    end;
get_line(State) ->
    get_line([], State).


get_line(Acc, {S, <<10, Tail/binary>>, Port}) ->
    {lists:reverse(Acc), {S, Tail, Port}};
get_line(Acc, {S, <<13, 10, Tail/binary>>, Port}) ->
    {lists:reverse(Acc), {S, Tail, Port}};
get_line(Acc, {middle, <<>>, Port}) ->
    get_line(Acc, add_cgi_resp(<<>>, Port));
get_line(Acc, {middle, <<13>>, Port}) ->          % We SHOULD test for CRLF.
    get_line(Acc, add_cgi_resp(<<13>>, Port));    % Would be easier without.
get_line(Acc, {ending, <<>>, Port}) ->
    {lists:reverse(Acc), {ending, <<>>, Port}};
get_line(Acc, {S, <<C, Tail/binary>>, Port}) ->
    get_line([C|Acc], {S, Tail, Port}).


add_cgi_resp(Bin, Port) ->
    receive
        {Port, {data,Data}} ->
            {middle, <<Bin/binary, Data/binary>>, Port};
        {Port, {exit_status, _Status}} ->
            ?Debug("~p~n", [{exit_status, _Status}]),            
            {ending, Bin, Port};
        _Other ->
            ?Debug("~p~n", [_Other]),
            add_cgi_resp(Bin, Port)
    end.



% @TODO: Figure out which of these we need: Exefilename, Scriptfilename, Pathinfo
%
fcgi_worker(Parent, Arg, ExeFileName, ScriptFileName, PathInfo, _ExtraEnv, _ServerConf) ->
    ?Debug("[fcgi_worker] ExeFileName=~p ScriptFileName=~p PathInfo=~p~n", [ExeFileName, ScriptFileName, PathInfo]),
    fgi_invoke_responder(Arg).


    
fgi_invoke_responder(Arg) -> 
    try
        Socket = fcgi_connect_to_application_server(Arg),        %% @@@ TODO: support timeout
        try                
            ok = fcgi_send_begin_request(Socket, ?FCGI_ROLE_RESPONDER, ?FCGI_CONFIG_KEEP_CONNECTION),
            ok = fcgi_send_params(Socket, fcgi_responder_cgi_params(Arg)),
%% @@@TODO: user ExtraEnv            
%%             case responder_additional_params(Arg) of
%%                 {ok, Params} -> ok = send_params(Socket, Params);
%%                 no_data -> ok
%%             end,
            ok = fcgi_send_params(Socket, []),
            case fcgi_responder_cgi_stdin_data(Arg) of
                {ok, StdinData} -> ok = fcgi_send_stdin(Socket, StdinData);
                no_data -> ok
            end,
            ok = fcgi_send_stdin(Socket, <<>>),
            {_AppStatus, _ProtStatus, StdOutData, _StdErrData} = fcgi_receive_reply(Socket),           % TODO: do something with appstatus and stderrdata
            ClientSocket = Arg#arg.clisock,
            ok = gen_tcp:send(ClientSocket, StdOutData),        %% TODO: this is a short term hack?
            ok                                                  %% TODO: explain
        catch
            exception:Reason1 ->
                gen_tcp:close(Socket),
                [{status, ?HTML_STATUS_INTERNAL_SERVER_ERROR}, {ehtml, {p, [], io:format("~p", [Reason1])}}]
        end,
        gen_tcp:close(Socket),
        ok                          
    catch
        exception:Reason2 ->
            [{status, ?HTML_STATUS_INTERNAL_SERVER_ERROR}, {ehtml, {p, [], io:format("~p", [Reason2])}}]
    end.          



fcgi_responder_cgi_params(Arg) ->
    %% @@@TODO: replace with messages
    no_data.



fcgi_responder_cgi_stdin_data(_Arg) ->
    %% @@@TODO: replace with messages
    no_data.



fcgi_choose_application_server(_Arg) ->
    {?FCGI_CONFIG_APPLICATION_SERVER_NAME, ?FCGI_CONFIG_APPLICATION_SERVER_PORT}.



fcgi_connect_to_application_server(Arg) ->
    {Name, Port} = fcgi_choose_application_server(Arg),
    Options = [binary, {packet, 0}, {active, false}],
    case gen_tcp:connect(Name, Port, Options, ?FCGI_CONFIG_CONNECT_TIMEOUT_MSECS) of
        {ok, Socket} ->
            Socket;
        {error, Reason} ->
            throw({could_not_connect_to_application_server, Name, Port, Reason})
    end.



fcgi_send_begin_request(Socket, Role, KeepConnection) ->
    Flags = case KeepConnection of
        true -> ?FCGI_KEEP_CONN;
        false -> ?FCGI_DONT_KEEP_CONN
    end,
    fcgi_send_record(Socket, ?FCGI_TYPE_BEGIN_REQUEST, ?FCGI_REQUEST_ID_APPLICATION, <<Role:16, Flags:8, 0:40>>).



fcgi_send_params(Socket, NameValueList) -> 
    fcgi_send_record(Socket, ?FCGI_TYPE_PARAMS, ?FCGI_REQUEST_ID_APPLICATION, NameValueList).



fcgi_send_stdin(Socket, Data) ->
    fcgi_send_record(Socket, ?FCGI_TYPE_STDIN, ?FCGI_REQUEST_ID_APPLICATION, Data).



fcgi_send_data(Socket, Data) ->
    fcgi_send_record(Socket, ?FCGI_TYPE_DATA, ?FCGI_REQUEST_ID_APPLICATION, Data).



fcgi_send_abort_request(Socket) ->
    fcgi_send_record(Socket, ?FCGI_TYPE_ABORT_REQUEST, ?FCGI_REQUEST_ID_APPLICATION, <<>>).



fcgi_send_record(Socket, Type, RequestId, NameValueList) ->
    EncodedRecord = fcgi_encode_record(Type, RequestId, NameValueList),
    case gen_tcp:send(Socket, EncodedRecord) of
        {error, Reason} ->
            throw({error_sending_record, Reason});
        ok ->
            ok
    end.



fcgi_encode_record(Type, RequestId, NameValueList) 
  when is_list(NameValueList) ->
    fcgi_encode_record(Type, RequestId, fcgi_encode_name_value_list(NameValueList));
    
fcgi_encode_record(Type, RequestId, ContentData) 
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
    <<Version:8,
      Type:8,
      RequestId:16,
      ContentLength:16,
      PaddingLength:8,
      Reserved:8,                                           %% TODO: The spec is not clear where this goes
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



fcgi_receive_reply(Socket) ->
    fcgi_receive_reply(Socket, [], []).

fcgi_receive_reply(Socket, StdOutDataList, StdErrDataList) ->
    {Type, ContentData} = fcgi_receive_record(Socket),
    case Type of
        ?FCGI_TYPE_END_REQUEST ->
            <<AppStatus:32, ProtStatus:8, _Reserved:24>> = ContentData,
            throw_if(ProtStatus < ?FCGI_STATUS_REQUEST_COMPLETE, {received_unknown_protocol_status, ProtStatus}),
            throw_if(ProtStatus > ?FCGI_STATUS_UNKNOWN_ROLE, {received_unknown_protocol_status, ProtStatus}),
            {AppStatus, ProtStatus, lists:reverse(StdOutDataList), lists:reverse(StdErrDataList)};
        ?FCGI_TYPE_STDOUT ->
            fcgi_receive_reply(Socket, [ContentData|StdOutDataList], StdErrDataList);
        ?FCGI_TYPE_STDERR ->
            fcgi_receive_reply(Socket, StdOutDataList, [ContentData|StdErrDataList]);
        ?FCGI_TYPE_UNKNOWN_TYPE ->
            <<Type:8, _Reserved:56>> = ContentData,
            throw({application_reported_unknown_type, Type})
    end.



fcgi_receive_record(Socket) ->
    case fcgi_receive_binary(Socket, 8, ?FCGI_CONFIG_READ_TIMEOUT_MSECS) of
        {error, Reason} ->
            throw({unable_to_read_record_header, Reason});
        {ok, <<Version:8, Type:8, RequestId:16, ContentLength:16, PaddingLength:8, _Reserved:8>>} ->
            throw_if(Version /= 1, {received_unsupported_version, Version}),
            case Type of
                ?FCGI_TYPE_END_REQUEST ->
                    throw_if(RequestId /= ?FCGI_REQUEST_ID_APPLICATION, {unexpected_request_id, RequestId}),
                    throw_if(ContentLength /= 8, {incorrect_content_length_for_end_request, ContentLength}),
                    ok;
                ?FCGI_TYPE_STDOUT ->
                    throw_if(RequestId /= ?FCGI_REQUEST_ID_APPLICATION, {unexpected_request_id, RequestId}),
                    ok;
                ?FCGI_TYPE_STDERR ->
                    throw_if(RequestId /= ?FCGI_REQUEST_ID_APPLICATION, {unexpected_request_id, RequestId}),
                    ok;
                ?FCGI_TYPE_UNKNOWN_TYPE ->
                    throw_if(RequestId /= ?FCGI_REQUEST_ID_MANAGEMENT, {unexpected_request_id, RequestId}),
                    throw_if(ContentLength /= 8, {incorrect_content_length_for_unknown_type, ContentLength}),
                    ok;
                OtherType ->
                    throw({received_unexpected_type, OtherType})
            end,
            case fcgi_receive_binary(Socket, ContentLength, ?FCGI_CONFIG_READ_TIMEOUT_MSECS) of
                {error, Reason} ->
                    throw({unable_to_read_content_data, Reason});
                {ok, ContentData} ->
                    case fcgi_receive_binary(Socket, PaddingLength, ?FCGI_CONFIG_READ_TIMEOUT_MSECS) of
                        {error, Reason} ->
                            throw({unable_to_read_record_padding_data, Reason});
                        {ok, _PaddingData} ->
                            {Type, ContentData}                            
                    end
            end
    end.


fcgi_receive_binary(_Socket, Length, _Timeout) when Length == 0 ->
    {ok, <<>>};

fcgi_receive_binary(Socket, Length, Timeout) ->
    gen_tcp:recv(Socket, Length, Timeout).



throw_if(Condition, Exception) ->
    if 
        Condition ->
            throw(Exception);
        true ->
            ok
    end.
