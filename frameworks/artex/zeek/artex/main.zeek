##! Agentic attack detections by ThreatDefence (ARTEX)
##! https://threatdefence.com/article/artex-agentic-attack-framework-detection-hunting
##!
##! Raises notices for ARTEX user agents, request headers and probe markers, the placeholder paths and
##! unsigned alg:none tokens ARTEX sends while mapping a web application, and ARTEX console pages
##! served in cleartext. Cleartext HTTP only: put it behind TLS decryption or on the inside of a
##! terminating proxy to see HTTPS traffic.
##!
##! Load with:  @load ./artex   (from the folder that holds this directory)
##! Indicators: load ../intel/artex.intel with the Intel framework (see README).

@load base/frameworks/notice
@load base/protocols/http

module ARTEX;

export {
    redef enum Notice::Type += {
        ## A request carried a user agent that names ARTEX or a renamed build. ATT&CK: T1595.002.
        User_Agent,
        ## A request carried an ARTEX header or probe marker. ATT&CK: T1595.002, T1190.
        Probe_Marker,
        ## A request asked for a placeholder path ARTEX uses to learn how a site answers. ATT&CK: T1595.002.
        Probe_Path,
        ## A request carried an unsigned JWT with alg none. ATT&CK: T1606, T1190.
        JWT_Alg_None,
        ## A server answered with an ARTEX console page. ATT&CK: T1071.001.
        Console_Page,
        ## A server answered with the Basic auth realm or the auth proxy header put in front of ARTEX consoles. ATT&CK: T1071.001.
        Console_Auth,
    };

    ## User agents that name ARTEX, its forks and renamed builds. The name is the indicator, so case is ignored:
    ## ARTEX-PENTEST/1.0 and ScopeWeaver/1.0 match. "artex/1.0" must start the string or follow a character that
    ## is not a letter or digit, so a longer word that ends in "artex" does not match.
    const user_agents: pattern =
        /(?i:artex-(readonly|pentest|audit|verify|spawn|enrich)\/)/ |
        /(?i:artex-worker\/)/ | /(?i:artex-i21861-canary)/ |
        /(?i:artex-agent)/ | /(?i:artex-judge-)/ |
        /(?i:Mozilla\/5\.0 \(ARTEX\))/ | /(?i:artexverify\/)/ |
        /^(?i:artex\/1\.0)/ | /(?i:[^a-z0-9]artex\/1\.0)/ |
        /(?i:scopeweaver)/ | /(?i:spa-api-recon)/ &redef;

    ## User agents where the case is the indicator, matched exactly. "ARTeX" was seen on its own and in
    ## "ARTeX-authorized-pentest"; with case ignored, "artex" is inside ordinary words such as SmartExplorer.
    const user_agents_exact: pattern = /ARTeX/ &redef;

    ## Placeholder paths and probe values in request URIs.
    const probe_paths: pattern =
        /zzz-nonexistent-xyz123/ | /zzz_nonexistent_abc\.txt/ | /Notexist-xyz/ |
        /code=AAAA&state=notvalidb64!!/ &redef;

    ## Probe marker strings in request URIs.
    const probe_markers: pattern =
        /ARTEX_WRITE_PROBE/ | /ARTX_PERSIST_OK/ | /artex_control_marker_zz9q/ |
        /ARTEX-PROBE-/ | /artex-probe-/ &redef;

    ## Base64url header prefixes of unsigned JWTs: {"alg":"none" with or without typ after it, typ first, and
    ## the None and NONE spellings. Base64 is case-sensitive, so these are matched exactly.
    const alg_none_jwt: pattern =
        /eyJhbGciOiJub25lI/ | /eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lI/ |
        /eyJhbGciOiJOb25lI/ | /eyJhbGciOiJOT05FI/ &redef;

    ## Console page titles: ARTEX, renamed builds ScopeWeaver and LUCK.
    const console_titles: pattern =
        /<title>(ARTEX|ScopeWeaver|LUCK)[ :\-<]/ &redef;

    ## Text that renamed builds keep: the Japanese title ending, and the description of the Pojun derivative
    ## (chu0119/Pojun, web/src/config/app-config.ts:13), whose title is only "Console".
    const console_text: pattern =
        /\xe8\x87\xaa\xe5\xbe\x8b\xe5\x9e\x8b\xe3\x83\x9a\xe3\x83\x8d\xe3\x83\x88\xe3\x83\xac\xe3\x83\xbc\xe3\x82\xb7\xe3\x83\xa7\xe3\x83\xb3\xe3\x83\x86\xe3\x82\xb9\xe3\x83\x88\xe3\x82\xb3\xe3\x83\xb3\xe3\x82\xbd\xe3\x83\xbc\xe3\x83\xab/ |
        /content=\x22Authorized operations console\x22/ &redef;

    ## Basic auth realms put in front of ARTEX consoles: ARTEX, ARTEX Gateway, ARTEX Console, ARTEX Admin and others.
    ## Artex is also a company name, so a match is probable, not certain.
    const console_realm: pattern = /(?i:realm=\x22artex[\x22 ])/ &redef;

    ## How long to suppress repeat notices for the same source and indicator.
    const suppress_for: interval = 1hr &redef;
}

function raise(c: connection, note: Notice::Type, msg: string, sub: string)
    {
    NOTICE([$note=note, $msg=msg, $sub=sub, $conn=c,
            $identifier=cat(c$id$orig_h, note, sub),
            $suppress_for=suppress_for]);
    }

event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string)
    {
    if ( probe_paths in original_URI )
        raise(c, Probe_Path, fmt("ARTEX probe path from %s", c$id$orig_h), original_URI);

    if ( probe_markers in original_URI )
        raise(c, Probe_Marker, fmt("ARTEX probe marker in URI from %s", c$id$orig_h), original_URI);

    if ( alg_none_jwt in original_URI )
        raise(c, JWT_Alg_None, fmt("Unsigned alg:none JWT in URI from %s", c$id$orig_h), original_URI);
    }

event http_all_headers(c: connection, is_orig: bool, hlist: mime_header_list)
    {
    if ( ! is_orig )
        {
        for ( j in hlist )
            {
            local r = hlist[j];

            if ( r$name == "WWW-AUTHENTICATE" && console_realm in r$value )
                raise(c, Console_Auth, fmt("ARTEX Basic auth realm served by %s:%s", c$id$resp_h, c$id$resp_p), r$value);

            else if ( r$name == "X-ARTEX-AUTH" )
                raise(c, Console_Auth, fmt("X-Artex-Auth header served by %s:%s", c$id$resp_h, c$id$resp_p), r$value);
            }
        return;
        }

    for ( i in hlist )
        {
        local h = hlist[i];

        if ( h$name == "USER-AGENT" && ( user_agents in h$value || user_agents_exact in h$value ) )
            raise(c, User_Agent, fmt("ARTEX user agent from %s", c$id$orig_h), h$value);

        else if ( h$name == "X-ARTX-KEY" )
            raise(c, Probe_Marker, fmt("X-ARTX-KEY header from %s", c$id$orig_h), h$value);

        else if ( h$name == "AUTHORIZATION" && alg_none_jwt in h$value )
            raise(c, JWT_Alg_None, fmt("Unsigned alg:none JWT in Authorization from %s", c$id$orig_h), h$name);
        }
    }

event http_entity_data(c: connection, is_orig: bool, length: count, data: string)
    {
    if ( is_orig )
        return;

    if ( console_titles in data || console_text in data )
        raise(c, Console_Page, fmt("ARTEX console page served by %s:%s", c$id$resp_h, c$id$resp_p),
              cat(c$id$resp_h, ":", c$id$resp_p));
    }
