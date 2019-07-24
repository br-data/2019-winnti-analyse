path = input('Locate the file: \n')

def xoring(pattern, key):
    xor_this = "0x" + pattern
    xor_this = int(xor_this, 16)
    with_that = "0x" + key
    with_that = int(with_that, 16)
    return hex(xor_this ^ with_that)

with open(path, "rb") as f:
    hex_file = bytearray(f.read()).hex().replace("\n", "")
    file_pattern = "daa0c7cbf4f0" + hex_file.split("daa0c7cbf4f0")[1]


# iterating over the bytes
# via https://stackoverflow.com/questions/434287/what-is-the-most-pythonic-way-to-iterate-over-a-list-in-chunks
def chunker(seq, size):
    return [seq[pos:pos + size] for pos in range(0, len(seq), size)]

hex_list = [ "0" + str(hex(number).replace('0x','')).upper() if len(hex(number).replace('0x','')) < 2
            else "0" + str(number).upper() if len(hex(number).replace('0x','')) < 2 
            else hex(number).replace('0x','').upper() 
            for number in range(256)]

pattern_list = [group for group in chunker(file_pattern, 2)]

xored_list=[]
starting_point = 153

for pattern in pattern_list:
    if starting_point == len(hex_list):
        starting_point = 0
        xored_list.append(xoring(pattern, hex_list[starting_point]))
        starting_point += 1
    else:
        xored_list.append(xoring(pattern, hex_list[starting_point]))
        starting_point += 1

all_items = []

for item in xored_list:
    try:
        if int(item,16) < 0x20:
            all_items.append(" ")
        elif int(item,16) >=0x20 and int(item,16) <= 0x7E:
            all_items.append(chr(int(item,16)))
        else:
            all_items.append(" ")
    except ValueError as e:
        print(item, e)

joined_string = ''.join(all_items)
print(joined_string)
