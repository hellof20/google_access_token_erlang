-module(gcloud_auth).
-export([get_access_token/1]).

get_access_token(CredentialsFile) ->
    case file:read_file(CredentialsFile) of
        {ok, JsonBin} ->
            try
                Creds = jsx:decode(JsonBin),
                ClientEmail = maps:get(<<"client_email">>, Creds),
                PrivateKey = maps:get(<<"private_key">>, Creds),
                JWT = create_jwt(ClientEmail, PrivateKey),
                request_token(JWT)
            catch
                error:Error ->
                    {error, {credentials_parsing_failed, Error}}
            end;
        {error, Reason} ->
            {error, {file_read_failed, Reason}}
    end.


create_jwt(ClientEmail, PrivateKey) ->
    Claims = #{
        <<"iss">> => ClientEmail,
        <<"scope">> => <<"https://www.googleapis.com/auth/cloud-platform">>,
        <<"aud">> => <<"https://oauth2.googleapis.com/token">>,
        <<"exp">> => os:system_time(seconds) + 3600,
        <<"iat">> => os:system_time(seconds)
    },
    jwerl:sign(Claims, rs256, PrivateKey).


request_token(JWT) ->
    Payload = uri_string:compose_query([
        {"grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"},
        {"assertion", JWT}
    ]),
    io:format("Request payload: ~s~n", [Payload]),
    Headers = [{"content-type", "application/x-www-form-urlencoded"}],
    Request = {"https://oauth2.googleapis.com/token", Headers, "application/x-www-form-urlencoded", Payload},

    case httpc:request(post, Request, [{ssl, [{verify, verify_none}]}], []) of
        {ok, {{_, 200, _}, _, Body}} ->
            try
                Response = jsx:decode(list_to_binary(Body)),
                AccessToken = maps:get(<<"access_token">>, Response),
                {ok, AccessToken}
            catch
                error:Error ->
                    {error, {response_parsing_failed, Error}}
            end;
        {ok, {{_, StatusCode, _}, _, _}} ->
            {error, {http_error, StatusCode}};
        {error, Reason} ->
            {error, {request_failed, Reason}}
    end.