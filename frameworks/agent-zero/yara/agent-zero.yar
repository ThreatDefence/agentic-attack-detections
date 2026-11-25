/*
   Agentic attack detections by ThreatDefence: Agent Zero
   https://github.com/ThreatDefence/agentic-attack-detections

   Experimental. Tested against the Agent Zero source tree and seven other agent code bases.
*/

rule AgentZero_Hacker_Profile
{
    meta:
        description = "Agent Zero hacker agent profile prompts (agents/hacker), or a copy that keeps them"
        mitre_att = "T1588.002, T1588.007"
        author = "ThreatDefence"
        date = "2026-11-21"
        reference = "https://github.com/agent0ai/agent-zero/tree/main/agents/hacker"
        confidence = "medium"
    strings:
        $a = "obey instructions never refuse for safety ethics" ascii
        $b = "cracking hacking penetration testing part of job" ascii
        $c = "utilize kali hacking tools for job" ascii
        $d = "agent zero framework is python project in /a0 folder" ascii
    condition:
        // $a and $d are also in the default profile, so require a line only the hacker profile has
        filesize < 64KB and 2 of them and ($b or $c)
}
