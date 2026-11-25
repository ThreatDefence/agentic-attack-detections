##! An AI agent's page reader on your application next to attack traffic from the same address (behaviors hunt 03)
##!
##! Agent CLIs read pages with their own fetch tools and attack through curl, Python and Kali tools in their shell:
##! Qwen Code ("QwenCode/<version> (<os>; <arch>)"), Kimi CLI ("KimiCLI/<version>"), opencode
##! ("opencode/<channel>/<version>/<name>") and Claude Code ("Claude-User (claude-code/<version>; ...)", which Cairn's
##! workers run with DeepSeek behind it). A reader hit alone means little: ordinary users send the same strings. The
##! same address sending reader requests and tool traffic or payloads to one host within the window is an AI agent
##! attacking that host.
##!
##! State is kept only for addresses that sent a page read, never for every visitor. Attack traffic is paired with a
##! page read that came before it; an agent keeps attacking after it reads, so the next attack request pairs.
##!
##! Cluster: a worker that sees a page read tells the manager, and the manager tells every worker. Each worker pairs
##! the attack traffic it sees with that shared list and raises the notice itself. A single process skips the
##! messages and uses the list directly.

@load base/protocols/http
@load ./main

module AgenticBehaviors;

export {
    redef enum Notice::Type += {
        ## One address sent AI agent page reads and attack tool traffic or payloads to the same host. ATT&CK: T1594, T1190.
        AI_Agent_Attacking_Site,
    };

    ## User agents of AI agent page readers and search tools.
    const agent_reader_user_agents: pattern =
        /Claude-User \(claude-code\// | /^QwenCode\// | /^KimiCLI\// | /^opencode\// &redef;

    ## How long a page read is remembered for pairing.
    const page_reader_window: interval = 1hr &redef;

    ## Worker to manager: this address read this host with a page reader.
    global reader_seen: event(src: addr, host: string);
    ## Manager to workers: remember it.
    global reader_known: event(src: addr, host: string);
}

# Address and host of each page read, on every node that inspects traffic.
global readers: set[addr, string] &create_expire=page_reader_window;

event AgenticBehaviors::reader_seen(src: addr, host: string)
    {
    Cluster::publish(Cluster::worker_topic, AgenticBehaviors::reader_known, src, host);
    }

event AgenticBehaviors::reader_known(src: addr, host: string)
    {
    add readers[src, host];
    }

event http_all_headers(c: connection, is_orig: bool, hlist: mime_header_list)
    {
    if ( ! is_orig || ! c?$http )
        return;
    local ua = c$http?$user_agent ? c$http$user_agent : "";
    local host = c$http?$host ? to_lower(c$http$host) : cat(c$id$resp_h);
    local uri = c$http?$uri ? c$http$uri : "";
    local src = c$id$orig_h;

    if ( agent_reader_user_agents in ua )
        {
        # One message per address and host per window, however many pages it reads.
        if ( [src, host] !in readers )
            {
            add readers[src, host];
            if ( Cluster::is_enabled() )
                Cluster::publish(Cluster::manager_topic, AgenticBehaviors::reader_seen, src, host);
            }
        }
    else if ( [src, host] in readers && ( tool_user_agents in ua || payload_uri in uri ) )
        raise(c, AI_Agent_Attacking_Site,
              fmt("%s read %s with an AI agent's page reader and sent attack traffic", src, host),
              fmt("%s %s", ua, uri), cat(src, host));
    }
