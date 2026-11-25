##! Agentic attack detections: AutoCVE
##! https://github.com/ThreatDefence/agentic-attack-detections
##!
##! Raises notices for an AutoCVE API answering its root path and an AutoCVE console page. Both are what a server
##! running AutoCVE sends, so they find AutoCVE on your network, not AutoCVE testing you: it audits source code and
##! sends nothing to the audited project. See frameworks/autocve/source-code-signals.md for where each signal comes from.
##!
##! The stock Docker stack serves the console on 3000 and the API on 8000 as plain HTTP.
##!
##! Load with:  @load /path/to/frameworks/autocve/zeek/autocve

@load base/frameworks/notice
@load base/protocols/http

module AutoCVE;

export {
    redef enum Notice::Type += {
        ## A server answered with the AutoCVE API welcome. ATT&CK: T1071.001.
        API_Exposed,
        ## A server answered with the AutoCVE console page. ATT&CK: T1071.001.
        Console_Page,
    };

    ## GET / on the API (backend/app/main.py:122-130). Both strings are in the same short JSON answer.
    const api_welcome: pattern = /Welcome to AutoCVE API/ &redef;
    const api_demo: pattern = /demo_account/ &redef;

    ## The console title (frontend/index.html:8).
    const console_title: pattern = /<title>AutoCVE<\/title>/ &redef;

    ## How long to suppress repeat notices for the same server and signal.
    const suppress_for: interval = 1hr &redef;
}

function raise(c: connection, note: Notice::Type, msg: string)
    {
    local where = cat(c$id$resp_h, ":", c$id$resp_p);
    NOTICE([$note=note, $msg=msg, $sub=where, $conn=c,
            $identifier=cat(where, note), $suppress_for=suppress_for]);
    }

event http_entity_data(c: connection, is_orig: bool, length: count, data: string)
    {
    if ( is_orig )
        return;

    if ( api_welcome in data && api_demo in data )
        raise(c, API_Exposed, fmt("AutoCVE API answering on %s:%s", c$id$resp_h, c$id$resp_p));

    if ( console_title in data )
        raise(c, Console_Page, fmt("AutoCVE console page served by %s:%s", c$id$resp_h, c$id$resp_p));
    }
