rule BannedWords001 {
    meta:
        Author = "InforGuard"
        Description = "Banned Words in China."
    
    strings:
        $words_001 = "傻逼"
        $words_002 = "伊斯兰国"
        $words_003 = "反共"
        $words_004 = "黄皮肤俄罗斯狗腿"
        $words_005 = "环球时报"
        $words_006 = "鸡巴"
        $words_007 = "反华"
        $words_008 = "美狗"
        $words_009 = "操你妈"
        $words_010 = "二逼"
        $words_011 = "滚下台"
        $words_012 = "屁民"
        $words_013 = "卧槽"
        $words_014 = "五毛"
        $words_015 = "辱华"
    
    condition:
        any of them
}
