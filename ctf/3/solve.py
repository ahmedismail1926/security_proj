data = "134 154 160 156 246 196 210 110 190 230 208 210 204 110 210 220 206 190 210 230 190 238 102 104 214 250"
numbers = map(int, data.split())
flag = "".join(chr(n >> 1) for n in numbers)
print("Flag:", flag)

with open("flag.txt", "w") as f:
    f.write(flag)
