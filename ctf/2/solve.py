from PIL import Image
import numpy as np

img1_path = r"a:\University\Spring2026\Security\Project\security_proj\ctf\CTF_DATA\CTF2\Layer1.png"
img2_path = r"a:\University\Spring2026\Security\Project\security_proj\ctf\CTF_DATA\CTF2\Layer2.png"

img1 = Image.open(img1_path).convert('RGB')
img2 = Image.open(img2_path).convert('RGB')

arr1 = np.array(img1)
arr2 = np.array(img2)

# Try XOR
xor_arr = np.bitwise_xor(arr1, arr2)
xor_img = Image.fromarray(xor_arr)
xor_img.save("xor_result.png")

# Also try addition and subtraction just in case
add_arr = np.clip(arr1 + arr2, 0, 255).astype(np.uint8)
add_img = Image.fromarray(add_arr)
add_img.save("add_result.png")

sub_arr = np.clip(arr1 - arr2, 0, 255).astype(np.uint8)
sub_img = Image.fromarray(sub_arr)
sub_img.save("sub_result.png")

# Also try abs difference
diff_arr = np.abs(arr1.astype(np.int16) - arr2.astype(np.int16)).astype(np.uint8)
diff_img = Image.fromarray(diff_arr)
diff_img.save("diff_result.png")

print("Generated xor_result.png, add_result.png, sub_result.png, diff_result.png")
