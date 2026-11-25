##! Agentic attack detections: HexStrike
##! https://github.com/ThreatDefence/agentic-attack-detections
##!
##! Raises notices for HexStrike's user agents and XSS probe on your web servers, requests to the HexStrike tool
##! API, and a HexStrike server answering its health check. See frameworks/hexstrike/source-code-signals.md for
##! where each signal comes from in the code.
##!
##! The tool API on 8888 is plain HTTP. Requests to your own sites need cleartext HTTP or decrypted traffic.
##!
##! Load with:  @load /path/to/frameworks/hexstrike/zeek/hexstrike

@load base/frameworks/notice
@load base/protocols/http

module HexStrike;

export {
    redef enum Notice::Type += {
        ## A request carried the user agent of HexStrike's HTTP testing module or headless browser. ATT&CK: T1595.002.
        User_Agent,
        ## A request carried the user agent of an exploit script HexStrike generated. ATT&CK: T1190.
        Exploit_User_Agent,
        ## A request carried HexStrike's XSS reflection probe. ATT&CK: T1595.002, T1190.
        XSS_Probe,
        ## A request asked the HexStrike server to run a shell command or a tool. ATT&CK: T1059, T1071.001.
        Tool_API_Request,
        ## A server answered as a HexStrike server. ATT&CK: T1588.002.
        Server_Exposed,
    };

    ## HexStrike-HTTP-Framework/1.0 (Advanced Security Testing) and HexStrike-BrowserAgent/1.0 (Security Testing).
    const user_agents: pattern = /HexStrike-HTTP-Framework\// | /HexStrike-BrowserAgent\// &redef;

    ## The user agent of generated exploit scripts.
    const exploit_user_agent = "Mozilla/5.0 (Compatible Exploit)" &redef;

    ## The XSS probe it submits into every text field of a GET form.
    const xss_probe: pattern = /hexstrikeXSSTest123/ &redef;

    ## Tool API paths: /api/command runs any shell command, /api/tools/<tool> runs one tool.
    const api_paths: pattern = /^\/api\/command(\?|$)/ | /^\/api\/tools\/[^\/?]+/ &redef;

    ## Ports the HexStrike server listens on (HEXSTRIKE_PORT, 8888 by default).
    const api_ports: set[port] = { 8888/tcp } &redef;

    ## The health check answer.
    const health_answer: pattern = /HexStrike AI Tools API Server is operational/ &redef;

    ## How long to suppress repeat notices for the same source and signal.
    const suppress_for: interval = 1hr &redef;
}

function raise(c: connection, note: Notice::Type, msg: string, sub: string)
    {
    NOTICE([$note=note, $msg=msg, $sub=sub, $conn=c,
            $identifier=cat(c$id$orig_h, c$id$resp_h, note),
            $suppress_for=suppress_for]);
    }

event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string)
    {
    if ( xss_probe in original_URI )
        raise(c, XSS_Probe, fmt("HexStrike XSS probe from %s to %s", c$id$orig_h, c$id$resp_h), original_URI);

    if ( method == "POST" && c$id$resp_p in api_ports && api_paths in original_URI )
        raise(c, Tool_API_Request, fmt("HexStrike tool API %s from %s to %s:%s", original_URI, c$id$orig_h, c$id$resp_h, c$id$resp_p),
              original_URI);
    }

event http_all_headers(c: connection, is_orig: bool, hlist: mime_header_list)
    {
    if ( ! is_orig )
        return;

    for ( i in hlist )
        {
        local h = hlist[i];
        if ( h$name != "USER-AGENT" )
            next;

        if ( user_agents in h$value )
            raise(c, User_Agent, fmt("HexStrike user agent from %s to %s", c$id$orig_h, c$id$resp_h), h$value);
        else if ( h$value == exploit_user_agent )
            raise(c, Exploit_User_Agent, fmt("HexStrike exploit script user agent from %s to %s", c$id$orig_h, c$id$resp_h), h$value);
        }
    }

event http_entity_data(c: connection, is_orig: bool, length: count, data: string)
    {
    if ( ! is_orig && health_answer in data )
        raise(c, Server_Exposed, fmt("HexStrike server answering on %s:%s", c$id$resp_h, c$id$resp_p),
              cat(c$id$resp_h, ":", c$id$resp_p));
    }
