##! Agentic attack detections: LuaN1aoAgent
##! https://github.com/ThreatDefence/agentic-attack-detections
##!
##! Raises notices for the user agents of LuaN1aoAgent's research and fetch tools, and for its web workbench: the
##! page title and the CSRF cookie it sets. See frameworks/luan1aoagent/source-code-signals.md for where each signal
##! comes from in the code.
##!
##! The workbench (8787) is plain HTTP unless the operator puts TLS in front of it. Requests to your own sites need
##! cleartext HTTP or decrypted traffic.
##!
##! Load with:  @load /path/to/frameworks/luan1aoagent/zeek/luan1aoagent

@load base/frameworks/notice
@load base/protocols/http

module LuaN1aoAgent;

export {
    redef enum Notice::Type += {
        ## A request carried the research tool user agent LuaN1aoAgent/<version>. ATT&CK: T1595.002.
        User_Agent,
        ## A request carried the browser string of the fetch tool, which no real browser sends. ATT&CK: T1595.002.
        Browser_Imitation,
        ## A server answered with the LuaN1aoAgent workbench page or set its CSRF cookie. ATT&CK: T1071.001.
        Console_Page,
    };

    ## src/tools/research-tools.ts:10.
    const user_agent: pattern = /^LuaN1aoAgent\// &redef;

    ## src/tools/research-tools.ts:11: no "(KHTML, like Gecko)" and a two-part Chrome version.
    const browser_imitation = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/124.0 Safari/537.36" &redef;

    ## The page title 鸾鸟渗透智能体 (web/index.html:7).
    const console_title: pattern = /<title>\xe9\xb8\xbe\xe9\xb8\x9f\xe6\xb8\x97\xe9\x80\x8f\xe6\x99\xba\xe8\x83\xbd\xe4\xbd\x93/ &redef;

    ## The CSRF cookie the workbench sets (src/web-security.ts:5, 92).
    const csrf_cookie: pattern = /^luanniao_csrf=/ &redef;

    ## How long to suppress repeat notices for the same pair and signal.
    const suppress_for: interval = 1hr &redef;
}

function raise(c: connection, note: Notice::Type, msg: string, sub: string)
    {
    NOTICE([$note=note, $msg=msg, $sub=sub, $conn=c,
            $identifier=cat(c$id$orig_h, c$id$resp_h, note),
            $suppress_for=suppress_for]);
    }

event http_all_headers(c: connection, is_orig: bool, hlist: mime_header_list)
    {
    for ( i in hlist )
        {
        local h = hlist[i];

        if ( is_orig && h$name == "USER-AGENT" )
            {
            if ( user_agent in h$value )
                raise(c, User_Agent, fmt("LuaN1aoAgent research tool user agent from %s to %s", c$id$orig_h, c$id$resp_h), h$value);
            else if ( h$value == browser_imitation )
                raise(c, Browser_Imitation, fmt("LuaN1aoAgent fetch tool user agent from %s to %s", c$id$orig_h, c$id$resp_h), h$value);
            }

        else if ( ! is_orig && h$name == "SET-COOKIE" && csrf_cookie in h$value )
            raise(c, Console_Page, fmt("LuaN1aoAgent workbench cookie set by %s:%s", c$id$resp_h, c$id$resp_p),
                  cat(c$id$resp_h, ":", c$id$resp_p));
        }
    }

event http_entity_data(c: connection, is_orig: bool, length: count, data: string)
    {
    if ( ! is_orig && console_title in data )
        raise(c, Console_Page, fmt("LuaN1aoAgent workbench page served by %s:%s", c$id$resp_h, c$id$resp_p),
              cat(c$id$resp_h, ":", c$id$resp_p));
    }
