import myref

print('#define u8 unsigned char')
print('u8 RS[4][8] = {')
for i in myref.RS:
    print('    {', end=' ')
    for j in i:
        print("0x%02X," % j, end=' ')
    print('},')
print('};')
print()

print('u8 Q0[] = {')
print('   ', end='')
for i in range(256):
    print("0x%02X," % myref.Qpermute(i, myref.Q0), end=' ')
    if not ((i+1) % 8):
        print('\n   ', end='')
print('};')
print()

print('u8 Q1[] = {')
print('   ', end='')
for i in range(256):
    print("0x%02X," % myref.Qpermute(i, myref.Q1), end=' ')
    if not ((i+1) % 8):
        print('\n   ', end='')
print('};')
print()

print('u8 mult5B[] = {')
print('   ', end='')
for i in range(256):
    print("0x%02X," % myref.gfMult(0x5B, i, myref.GF_MOD), end=' ')
    if not ((i+1) % 8):
        print('\n   ', end='')
print('};')
print()

print('u8 multEF[] = {')
print('   ', end='')
for i in range(256):
    print("0x%02X," % myref.gfMult(0xEF, i, myref.GF_MOD), end=' ')
    if not ((i+1) % 8):
        print('\n   ', end='')
print('};')
print()