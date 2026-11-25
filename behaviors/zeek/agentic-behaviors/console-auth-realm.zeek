##! A server answering with a Basic auth realm named after an agentic attack framework
##!
##! Operators put nginx Basic auth in front of their consoles and name the realm after the tool: in Shodan on
##! November 25, 2026, 63 services answered realm="Cairn", 14 realm="CyberStrikeAI", 8 realm="PentAGI", and a few
##! HexStrike, RedAmon, Decepticon, open-kritt, T3MP3ST, Pojun and AntiFox (exposure/README.md). The realm is
##! set by the web server in front of the console, so a match is probable, not certain. ARTEX realms are
##! matched by the ARTEX script (ARTEX::Console_Auth), Hermes by its own rules.
##!
##! Cluster: each response is judged on its own.

@load base/protocols/http
@load ./main

module AgenticBehaviors;

export {
    redef enum Notice::Type += {
        ## A server answered 401 with a Basic auth realm that names an agentic attack framework. ATT&CK: T1071.001.
        Agent_Console_Realm,
    };

    ## Realm names, matched at the start of the realm and ended by a quote or a space.
    const console_realms: pattern =
        /(?i:realm=\x22(cairn|pentagi|cyberstrikeai|cyberstrike|hexstrike|redamon|decepticon|open-kritt|kritt|t3mp3st|pojun|antifox)[\x22 ])/ &redef;
}

event http_all_headers(c: connection, is_orig: bool, hlist: mime_header_list)
    {
    if ( is_orig )
        return;

    for ( i in hlist )
        {
        local h = hlist[i];
        if ( h$name == "WWW-AUTHENTICATE" && console_realms in h$value )
            raise(c, Agent_Console_Realm, fmt("Basic auth realm naming an agent framework served by %s:%s", c$id$resp_h, c$id$resp_p),
                  h$value, cat(c$id$resp_h, c$id$resp_p, "realm"));
        }
    }
