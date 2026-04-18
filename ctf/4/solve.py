from PIL import Image

def extract_lsb_channel(image_path, channel=0):
    img = Image.open(image_path).convert("RGB")
    pixels = img.load()
    w, h = img.size
    
    bits = ""
    for y in range(h):
        for x in range(w):
            bits += str(pixels[x, y][channel] & 1)
            
    chars = "".join([chr(int(bits[i:i+8], 2)) for i in range(0, len(bits)-8, 8)])
    
    if "CMPN{" in chars:
        idx = chars.find("CMPN{")
        end_idx = chars.find("}", idx)
        print(f"Flag found in channel {channel}:", chars[idx:end_idx+1])
        return chars[idx:end_idx+1]
    return None

if __name__ == "__main__":
    image_path = r"a:\University\Spring2026\Security\Project\security_proj\ctf\CTF_DATA\CTF4\stego.png"
    for ch in range(3):
        flag = extract_lsb_channel(image_path, ch)
        if flag:
            with open(r"a:\University\Spring2026\Security\Project\security_proj\ctf\4\flag.txt", "w") as f:
                f.write(flag)
            break

