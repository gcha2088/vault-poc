create or replace PACKAGE PL_VAULT_POC
AS

    PROCEDURE vault_demo(
        endpoint IN VARCHAR2,
        env      IN VARCHAR2
    );

    FUNCTION call_rest_get(
        url        IN    VARCHAR2,
        token      IN    VARCHAR2,
        result     OUT   VARCHAR2
    ) RETURN PLS_INTEGER;

    FUNCTION get_token(
        role_id   IN VARCHAR2,
        secret_id IN VARCHAR2,
        token     OUT VARCHAR2
    ) RETURN VARCHAR2;

    FUNCTION get_vault_syspar(
        i_config_flag_name IN system_vault_config.config_flag_name%TYPE
    ) RETURN VARCHAR2;

END PL_VAULT_POC;
/

create or replace PACKAGE BODY      PL_VAULT_POC
AS

    FUNCTION get_token(
        role_id   IN VARCHAR2,
        secret_id IN VARCHAR2,
        token     OUT VARCHAR2
    ) RETURN VARCHAR2 AS
        req                  UTL_HTTP.REQ;
        resp                 UTL_HTTP.RESP;
        resp_string          VARCHAR2(1000);
        url                  VARCHAR2(100);
        json_in              VARCHAR2(150);
        result               VARCHAR2(700);
        jo JSON_OBJECT_T;
        data JSON_ELEMENT_T;
        data_obj JSON_OBJECT_T;
    BEGIN
        url := 'http://10.133.72.44:8200/v1/auth/approle/login';
        json_in := '{"role_id":"'||role_id||'","secret_id":"'||secret_id||'"}';

        UTL_HTTP.SET_WALLET('');
        req := UTL_HTTP.BEGIN_REQUEST(
                url => url,
                method => 'POST',
                http_version => 'HTTP/1.1'
            );

        UTL_HTTP.SET_HEADER(req, 'content-type', 'application/json');
        UTL_HTTP.SET_HEADER(req, 'X-Vault-Request', 'true');
        UTL_HTTP.SET_HEADER( req, 'Content-Length', length(json_in) );
        UTL_HTTP.WRITE_TEXT( req, json_in );
        UTL_HTTP.set_persistent_conn_support(req, FALSE);
        resp := UTL_HTTP.GET_RESPONSE(req);

        IF resp.status_code = '200' AND resp.reason_phrase = 'OK'
        THEN
            BEGIN
                LOOP
                    UTL_HTTP.READ_LINE( resp, resp_string, TRUE ); -- read the response body
                    result:= result || resp_string;   --- setting the response body to OUT parameter "restul"
                END LOOP;
                UTL_HTTP.END_RESPONSE(resp);
            EXCEPTION
                WHEN UTL_HTTP.end_of_body THEN
                    UTL_HTTP.END_RESPONSE(resp);
            END;
            pl_log.ins_msg('INFO', 'CALL_REST_POST','CALL_REST_POST - RESPONSE MSG: '|| result ,  sqlcode, sqlerrm); -- for swms.log file
            jo := JSON_OBJECT_T.parse(result);
            data := jo.get('auth');
            data_obj := JSON_OBJECT_T.parse(data.to_string);
            token := data_obj.get_string('client_token');
            RETURN token;
        ELSE
            DBMS_OUTPUT.PUT_LINE('status_code is not 200');
            pl_log.ins_msg('FATAL', 'CALL_REST_POST','CALL_REST_POST - Resp.status_code=['|| resp.status_code || ']' || resp.reason_phrase ,  sqlcode, sqlerrm);
            RETURN result;
        END IF;

    EXCEPTION
        WHEN OTHERS THEN
            BEGIN
                pl_log.ins_msg('FATAL', 'CALL_REST_POST', 'CALL_REST_POST - UTL_HTTP EXCEPTION MSG: ' || UTL_HTTP.get_detailed_sqlerrm,  sqlcode, sqlerrm);
            END;
            UTL_HTTP.END_RESPONSE(resp);
            RETURN result;
    END get_token;

    FUNCTION call_rest_get(
        url        IN    VARCHAR2,
        token      IN    VARCHAR2,
        result     OUT   VARCHAR2
    ) RETURN PLS_INTEGER AS
        req                  UTL_HTTP.REQ;
        resp                 UTL_HTTP.RESP;
        resp_string          VARCHAR2(500);
    BEGIN
        req := UTL_HTTP.BEGIN_REQUEST(
                url => url,
                method => 'GET',
                http_version => 'HTTP/1.1'
            );

        pl_log.ins_msg('INFO', 'CALL_REST_GET', 'CALL_REST_GET - REQ URL: ' || url,  sqlcode, sqlerrm); -- for swms.log file

        UTL_HTTP.SET_HEADER(req, 'content-type', 'application/json');
        UTL_HTTP.SET_HEADER(req, 'X-Vault-Request', 'true');
        UTL_HTTP.SET_HEADER(req, 'X-Vault-Token', token);
        resp := UTL_HTTP.GET_RESPONSE(req);

        IF resp.status_code = '200' AND resp.reason_phrase = 'OK'
        THEN
            DBMS_OUTPUT.PUT_LINE('status_code = 200');
            BEGIN
                LOOP
                    UTL_HTTP.READ_LINE(resp, resp_string, true); -- read the response body
                    result := result || resp_string;   --- setting the response body to OUT parameter "restul"
                END LOOP;
                UTL_HTTP.END_RESPONSE(resp);
            EXCEPTION
                WHEN UTL_HTTP.end_of_body THEN
                    UTL_HTTP.END_RESPONSE(resp);
            END;
            pl_log.ins_msg('INFO', 'CALL_REST_GET', 'CALL_REST_GET - RESPONSE MSG: ' || result,  sqlcode, sqlerrm); -- for swms.log file
            RETURN(0);
        ELSE
            DBMS_OUTPUT.PUT_LINE('status_code is not 200');
            pl_log.ins_msg('FATAL', 'CALL_REST_GET', 'CALL_REST_GET - resp.status_code=[' || resp.status_code || '] ' || resp.reason_phrase ,  sqlcode, sqlerrm); -- for swms.log file
            pl_log.ins_msg('FATAL', 'CALL_REST_GET', 'CALL_REST_GET - Req not success : '||url ,  sqlcode, sqlerrm);
            result := resp.reason_phrase;
            RETURN(1);
        END IF;

    EXCEPTION
        WHEN OTHERS THEN
            BEGIN
                pl_log.ins_msg('FATAL', 'CALL_REST_GET', 'CALL_REST_GET - UTL_HTTP EXCEPTION MSG: ' || UTL_HTTP.get_detailed_sqlerrm
                    ,  sqlcode, sqlerrm);
                pl_log.ins_msg('FATAL', 'CALL_REST_GET', 'CALL_REST_GET - Req Failed : ' || url ,  sqlcode, sqlerrm);
                result:=sqlerrm;
                RETURN(1);
            END;
            UTL_HTTP.END_RESPONSE(resp);
    END call_rest_get;

    PROCEDURE vault_demo(
        endpoint IN VARCHAR2,
        env      IN VARCHAR2
    ) AS
        role_id VARCHAR2(50);
        secret_id VARCHAR2(50);
        token VARCHAR2(1000);
        outvar VARCHAR2 (500);
        username VARCHAR2(20);
        password VARCHAR2(20);
        url VARCHAR2(50);
        url_endpoint VARCHAR2(20);
        https_enabled VARCHAR2(1);
        data JSON_ELEMENT_T;
        data_obj JSON_OBJECT_T;
        jo JSON_OBJECT_T;
        rc PLS_INTEGER;
    BEGIN
        role_id := get_vault_syspar('S2S_CLIENT_ROLE_ID');
        secret_id := get_vault_syspar('S2S_CLIENT_SECRET_ID');
        token := get_token(role_id,secret_id, token);
        rc:=call_rest_get('http://10.133.72.44:8200/v1/'||endpoint||'/'||env, token ,outvar);

        IF rc = 0 THEN
            jo := JSON_OBJECT_T.parse(outvar);
            pl_log.ins_msg('INFO', 'CALL_REST_GET', 'Return Json: ' || jo.to_string,  sqlcode, sqlerrm);
            data := jo.get('data');
            data_obj := JSON_OBJECT_T.parse(data.to_string);
            username := data_obj.get_string('client_id');
            password := data_obj.get_string('client_pass');
            url      := data_obj.get_string('HTTP_URL');
            url_endpoint:= data_obj.get_string('HTTP_URL_END_POINT');
            https_enabled:= data_obj.get_string('HTTPS_ENABLED');
            DBMS_OUTPUT.put_line('client_id: ' || username);
            DBMS_OUTPUT.put_line('client_password: ' || password);
            DBMS_OUTPUT.put_line('http_url: ' || url);
            DBMS_OUTPUT.put_line('url_endpoint: ' || url_endpoint);
            DBMS_OUTPUT.put_line('https_enabled: ' || https_enabled);
            pl_log.ins_msg('INFO', 'CALL_REST_GET', 'username: ' || username || ' password: '|| password,  sqlcode, sqlerrm);
        ELSE
            pl_log.ins_msg('INFO', 'CALL_REST_GET', 'rc = 1, outvar: : ' || outvar,  sqlcode, sqlerrm);
        END IF;
    END vault_demo;

    FUNCTION get_vault_syspar(
        i_config_flag_name IN system_vault_config.config_flag_name%TYPE
    )
        RETURN VARCHAR2 IS
        l_syspar_value system_vault_config.config_flag_val%TYPE;
    BEGIN
        SELECT config_flag_val
        INTO l_syspar_value
        FROM system_vault_config
        WHERE config_flag_name = UPPER(i_config_flag_name);

        RETURN (l_syspar_value);

    EXCEPTION
        WHEN OTHERS THEN
            pl_log.ins_msg('FATAL', 'GET_VAULT_SYSPAR',
                           'GET_VAULT_SYSPAR - ERROR IN GETTING THE CONFIG PROPERTY: ' || sqlerrm, sqlcode,
                           sqlerrm);
            RAISE;
    END get_vault_syspar;
END PL_VAULT_POC;
