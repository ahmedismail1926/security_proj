import binascii

p = 11607228028223627369
q = 12405339649142310293
n = 143991606075158483660871570161405209117
e = 65537
c = 34130411904650996210426832018051041635

phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)
m = pow(c, d, n)
m_bytes = m.to_bytes((m.bit_length() + 7) // 8, 'big')
flag = m_bytes.decode('utf-8')
print('Flag:', flag)
