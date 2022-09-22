rule MaliciousLink {
    meta:
        Author = "InforGuard"
        Description = "Banned Words in China."
    
    strings:
        $link_001 = "www.pornhub.com"
        $link_002 = "www.epochtimes.com"
        $link_003 = "chinadigitaltimes.net"
        $link_004 = "bannedbook.org"
        $link_005 = "rfa.org"
    
    condition:
        any of them
}
