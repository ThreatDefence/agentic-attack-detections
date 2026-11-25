##! Agentic attack detections: CyberStrikeAI
##! https://github.com/ThreatDefence/agentic-attack-detections
##!
##! Raises notices for the CyberStrikeAI webshell manager and its OS probe, implant check-ins over HTTP and TCP,
##! the console's own user agent, and the console's self-signed certificate. See
##! frameworks/cyberstrikeai/source-code-signals.md for where each signal comes from in the code.
##!
##! HTTP signals need cleartext HTTP: implants on an http_beacon listener, the curl one-liner and webshells
##! over plain HTTP are cleartext. The certificate is only visible in a TLS 1.2 handshake.
##!
##! Load with:  @load /path/to/frameworks/cyberstrikeai/zeek/cyberstrikeai

@load base/frameworks/notice
@load base/frameworks/signatures
@load base/protocols/http
@load base/files/x509

module CyberStrikeAI;

export {
    redef enum Notice::Type += {
        ## A request carried the webshell manager's user agent. ATT&CK: T1505.003.
        Webshell_Manager,
        ## A request to a web server carried the webshell OS probe. ATT&CK: T1505.003, T1082.
        OS_Probe,
        ## A web server answered the OS probe, so a webshell ran the command. ATT&CK: T1505.003, T1082.
        OS_Probe_Answered,
        ## An implant checked in or polled for tasks over HTTP. ATT&CK: T1071.001.
        Implant_Checkin,
        ## A request carried the implant's default user agent, a Chrome string cut short. ATT&CK: T1071.001, T1036.012.
        Implant_User_Agent,
        ## A TCP connection opened with the TCP implant's CSB1 greeting. ATT&CK: T1095.
        TCP_Implant,
        ## A request carried the console's own user agent (recon APIs, chat gateways). ATT&CK: T1071.001.
        Console_User_Agent,
        ## A server presented the console's self-signed CyberStrikeAI certificate. ATT&CK: T1071.001, T1587.003.
        Console_Certificate,
    };

    ## The webshell manager's user agent: Mozilla/5.0 (compatible; CyberStrikeAI-WebShell/1.0).
    const webshell_user_agent: pattern = /CyberStrikeAI-WebShell\// &redef;

    ## The console's user agent: CyberStrikeAI/1.7.4 and other versions.
    const console_user_agent: pattern = /^CyberStrikeAI\// &redef;

    ## The implant's default user agent. Browsers always continue with (KHTML, like Gecko), so the whole value must match.
    const implant_user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" &redef;

    ## The first command on every new webshell and the answer from a Windows server.
    const os_probe: pattern = /OSPROBE_/ &redef;
    const os_probe_answer: pattern = /:OSPROBE_Windows_NT:END/ &redef;

    ## Implant paths that come with the X-Session-Token header.
    const checkin_uri: pattern = /\/check_in(\?|$)/ | /\/tasks\?session_id=/ &redef;

    ## Subject and issuer of the console certificate.
    const console_cert_name: pattern = /(^|,)CN=CyberStrikeAI(,|$)/ &redef;

    ## How long to suppress repeat notices for the same source and signal.
    const suppress_for: interval = 1hr &redef;
}

# The TCP_Implant notice below reports the match, so the signature framework's own notice is not needed.
redef Signatures::actions += { ["cyberstrikeai-tcp-implant-magic"] = Signatures::SIG_QUIET };

function raise(c: connection, note: Notice::Type, msg: string, sub: string)
    {
    NOTICE([$note=note, $msg=msg, $sub=sub, $conn=c,
            $identifier=cat(c$id$orig_h, c$id$resp_h, note),
            $suppress_for=suppress_for]);
    }

event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string)
    {
    if ( os_probe in original_URI )
        raise(c, OS_Probe, fmt("CyberStrikeAI webshell OS probe from %s to %s", c$id$orig_h, c$id$resp_h), original_URI);
    }

event http_all_headers(c: connection, is_orig: bool, hlist: mime_header_list)
    {
    if ( ! is_orig )
        return;

    local method = c?$http && c$http?$method ? c$http$method : "";
    local uri = c?$http && c$http?$uri ? c$http$uri : "";

    for ( i in hlist )
        {
        local h = hlist[i];

        if ( h$name == "USER-AGENT" )
            {
            if ( webshell_user_agent in h$value )
                raise(c, Webshell_Manager, fmt("CyberStrikeAI webshell manager from %s to %s", c$id$orig_h, c$id$resp_h), h$value);
            else if ( console_user_agent in h$value )
                raise(c, Console_User_Agent, fmt("CyberStrikeAI console user agent from %s", c$id$orig_h), h$value);
            else if ( h$value == implant_user_agent )
                raise(c, Implant_User_Agent, fmt("CyberStrikeAI implant user agent from %s to %s", c$id$orig_h, c$id$resp_h), h$value);
            }

        else if ( h$name == "X-IMPLANT-TOKEN" )
            raise(c, Implant_Checkin, fmt("CyberStrikeAI implant token header from %s to %s", c$id$orig_h, c$id$resp_h), uri);

        else if ( h$name == "X-SESSION-TOKEN" && checkin_uri in uri )
            raise(c, Implant_Checkin, fmt("CyberStrikeAI implant %s %s from %s to %s", method, uri, c$id$orig_h, c$id$resp_h), uri);
        }
    }

event http_entity_data(c: connection, is_orig: bool, length: count, data: string)
    {
    if ( is_orig )
        {
        if ( os_probe in data )
            raise(c, OS_Probe, fmt("CyberStrikeAI webshell OS probe in a request body from %s to %s", c$id$orig_h, c$id$resp_h),
                  c?$http && c$http?$uri ? c$http$uri : "");
        }
    else if ( os_probe_answer in data )
        raise(c, OS_Probe_Answered, fmt("Webshell on %s answered the CyberStrikeAI OS probe", c$id$resp_h),
              c?$http && c$http?$uri ? c$http$uri : "");
    }

event signature_match(state: signature_state, msg: string, data: string)
    {
    if ( state$sig_id != "cyberstrikeai-tcp-implant-magic" )
        return;

    local c = state$conn;
    raise(c, TCP_Implant, fmt("CyberStrikeAI TCP implant greeting from %s to %s:%s", c$id$orig_h, c$id$resp_h, c$id$resp_p),
          cat(c$id$resp_h, ":", c$id$resp_p));
    }

event x509_certificate(f: fa_file, cert_ref: opaque of x509, cert: X509::Certificate)
    {
    if ( console_cert_name !in cert$subject || console_cert_name !in cert$issuer || ! f?$conns )
        return;

    for ( cid, c in f$conns )
        raise(c, Console_Certificate, fmt("CyberStrikeAI console certificate served by %s:%s", c$id$resp_h, c$id$resp_p),
              cert$subject);
    }
