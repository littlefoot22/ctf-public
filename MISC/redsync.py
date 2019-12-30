sync1 = 0x6B8B4567  #0x804c264
sync2 = 0x327B23C6  #0x804c268
sync3 = 0x643C9869  #0x804c26c

index = 0x643c9869 & 0x1f
local_4h = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
where_at = local_4h[index]
print(where_at)

i = 1
while i < 19:
    i += 1
    shr5 = sync3 >> 0x5
    shl1b = sync2 << 0x1b
    sync3 = shr5 | shl1b     #0x804c26c
    shr5 = sync2 >> 0x5
    shl1b = sync1 << 0x1b
    sync2 = shr5 | shl1b     #0x804c268
    sync1 = sync1 >> 0x5     #0x804c264
    where_at = local_4h[sync3 & 0x1f]
    print(where_at)

