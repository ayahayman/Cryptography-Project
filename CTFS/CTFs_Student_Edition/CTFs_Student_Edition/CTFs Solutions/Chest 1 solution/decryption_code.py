def reverse_alpha(ch):
    if 'a' <= ch <= 'z':
        return chr(219 - ord(ch))  
    elif 'A' <= ch <= 'Z':
        return chr(155 - ord(ch)) 
    else:
        return ch


with open('enc.txt', 'r') as file:
    enc_lines = file.readlines()
    
    with open('dec.txt', 'w') as out_file:
        for line in enc_lines:
            if line == '\n':
                out_file.write('\n')
                continue
            else:
                dec_line = ''.join(reverse_alpha(ch) for ch in line.rstrip('\n'))
                out_file.write(dec_line + '\n')
            