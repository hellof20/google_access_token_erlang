-module(main).
-export([start/0]).

start() ->
    application:ensure_all_started(ssl),
    application:ensure_all_started(inets),
    CredentialsFile = "spyderviews-sa.json",
    case gcloud_auth:get_access_token(CredentialsFile) of
        {ok, AccessToken} ->
            io:format("Access Token: ~s~n", [AccessToken]);
        {error, Reason} ->
            io:format("Error: ~p~n", [Reason])
    end.