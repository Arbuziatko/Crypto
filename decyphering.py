__author__ = 'Sabina'


def xor_strings(xs,ys):
    return "".join(chr(ord(x) ^ ord(y)) for x, y in zip(xs.decode("hex"), ys.decode("hex"))).encode("hex")


def space_possible(xc,yc,c):
    """ First xoring xc xor 20 to get a key, then yc xor key to check if the letter is lowercase of c
    """
    possible_key = xor_strings(xc, "20")
    possible_letter = xor_strings(yc, possible_key)
    if int(c, 16) + 32 == int(possible_letter, 16):
        return True


def check_spaces(xs, ys, key_list):
    xored_str = xor_strings(xs, ys)
    for j in range(0, len(xored_str), 2):
            if int(xored_str[j:j+2], 16) < 91 and int(xored_str[j:j+2], 16) > 64:
                if space_possible(xs[j:j+2],ys[j:j+2],xored_str[j:j+2]):
                    key_list[(j/2)] = xor_strings(xs[j:j+2], "20")

    return key_list


def key_generator(str,sl,index):
    return xor_strings(sl[index],str.encode("hex"))


def string_to_hex_list(xs):
    xs_list = list()
    for j in range(0, len(xs), 2):
        xs_list.append(xs[j:j+2])

    return xs_list


def possible_letter(xs_list,key,index):
    return xor_strings(xs_list[index],key)


def decypher(sl, key):
    for str in sl:
        temp = ""
        for char in xor_strings(str,key).decode("hex"):
            temp += chr(ord(char))
        print temp


def hex_to_character(xc):
    return "".join(chr(ord(char)) for char in xc.decode("hex"))


def fit(key_list, l):
    j = 0;
    for key in key_list:
        if key != "00":
            temp = ""
            print "Index:" + str(j)
            for i in range(0,11):
                temp += hex_to_character(possible_letter(string_to_hex_list(l[i]), key, j))
            print temp
        j += 1


def decrypt_messages(msgs, key):
    for msg in msgs:
        msg_list = string_to_hex_list(msg)
        i = 0
        for k in key:
            if k != "00":
                msg_list[i] = hex_to_character(xor_strings(msg_list[i], k))
            else:
                msg_list[i] = "-"
            i += 1
        print "".join(msg_list)

if __name__ == "__main__":
    l = ["315c4eeaa8b5f8aaf9174145bf43e1784b8fa00dc71d885a804e5ee9fa40b16349c146fb778cdf2d3aff021dfff5b403b510d0d0455468aeb98622b137dae857553ccd8883a7bc37520e06e515d22c954eba5025b8cc57ee59418ce7dc6bc41556bdb36bbca3e8774301fbcaa3b83b220809560987815f65286764703de0f3d524400a19b159610b11ef3e",
        "234c02ecbbfbafa3ed18510abd11fa724fcda2018a1a8342cf064bbde548b12b07df44ba7191d9606ef4081ffde5ad46a5069d9f7f543bedb9c861bf29c7e205132eda9382b0bc2c5c4b45f919cf3a9f1cb74151f6d551f4480c82b2cb24cc5b028aa76eb7b4ab24171ab3cdadb8356f",
        "32510ba9a7b2bba9b8005d43a304b5714cc0bb0c8a34884dd91304b8ad40b62b07df44ba6e9d8a2368e51d04e0e7b207b70b9b8261112bacb6c866a232dfe257527dc29398f5f3251a0d47e503c66e935de81230b59b7afb5f41afa8d661cb",
        "32510ba9aab2a8a4fd06414fb517b5605cc0aa0dc91a8908c2064ba8ad5ea06a029056f47a8ad3306ef5021eafe1ac01a81197847a5c68a1b78769a37bc8f4575432c198ccb4ef63590256e305cd3a9544ee4160ead45aef520489e7da7d835402bca670bda8eb775200b8dabbba246b130f040d8ec6447e2c767f3d30ed81ea2e4c1404e1315a1010e7229be6636aaa",
        "3f561ba9adb4b6ebec54424ba317b564418fac0dd35f8c08d31a1fe9e24fe56808c213f17c81d9607cee021dafe1e001b21ade877a5e68bea88d61b93ac5ee0d562e8e9582f5ef375f0a4ae20ed86e935de81230b59b73fb4302cd95d770c65b40aaa065f2a5e33a5a0bb5dcaba43722130f042f8ec85b7c2070",
        "32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd2061bbde24eb76a19d84aba34d8de287be84d07e7e9a30ee714979c7e1123a8bd9822a33ecaf512472e8e8f8db3f9635c1949e640c621854eba0d79eccf52ff111284b4cc61d11902aebc66f2b2e436434eacc0aba938220b084800c2ca4e693522643573b2c4ce35050b0cf774201f0fe52ac9f26d71b6cf61a711cc229f77ace7aa88a2f19983122b11be87a59c355d25f8e4",
        "32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd90f1fa6ea5ba47b01c909ba7696cf606ef40c04afe1ac0aa8148dd066592ded9f8774b529c7ea125d29"
        "8e8883f5e9305f4b44f915cb2bd05af51373fd9b4af511039fa2d96f83414aaaf261bda2e97b170fb5cce2a53e675c154c0d9681596934777e2275b381ce2e40582afe67650b13e72287ff2270abcf73bb028932836fbdecfecee0a3b894473c1bbeb6b4913a536ce4f9b13f1efff71ea313c8661dd9a4ce",
        "315c4eeaa8b5f8bffd11155ea506b56041c6a00c8a08854dd21a4bbde54ce56801d943ba708b8a3574f40c00fff9e00fa1439fd0654327a3bfc860b92f89ee04132ecb9298f5fd2d5e4b45e40ecc3b9d59e9417df7c95bba410e9aa2ca24c5474da2f276baa3ac325918b2daada43d6712150441c2e04f6565517f317da9d3",
        "271946f9bbb2aeadec111841a81abc300ecaa01bd8069d5cc91005e9fe4aad6e04d513e96d99de2569bc5e50eeeca709b50a8a987f4264edb6896fb537d0a716132ddc938fb0f836480e06ed0fcd6e9759f40462f9cf57f4564186a2c1778f1543efa270bda5e933421cbe88a4a52222190f471e9bd15f652b653b7071aec59a2705081ffe72651d08f822c9ed6d76e48b63ab15d0208573a7eef027",
        "466d06ece998b7a2fb1d464fed2ced7641ddaa3cc31c9941cf110abbf409ed39598005b3399ccfafb61d0315fca0a314be138a9f32503bedac8067f03adbf3575c3b8edc9ba7f537530541ab0f9f3cd04ff50d66f1d559ba520e89a2cb2a83",
        "32510ba9babebbbefd001547a810e67149caee11d945cd7fc81a05e9f85aac650e9052ba6a8cd8257bf14d13e6f0a803b54fde9e77472dbff89d71b5"
        "7bddef121336"
        "cb85"
        "ccb8f3"
        "315f4b"
        "52"
        "e301d16e9f52f904"]
    target = "32510ba9babebbbefd001547a810e67149caee11d945cd7fc81a05e9f85aac650e9052ba6a8cd8257bf14d13e6f0a803b54fde9e77472dbff89d71b57bddef121336cb85ccb8f3315f4b52e301d16e9f52f904"

    # print l
    # key_list = ["00" for x in range(len(target)/2)]
    # key_list = check_spaces(l,target,key_list)
    # print key_list
    #
    key_prob = ["00" for x in range(len(target)/2)]
    key_prob = check_spaces(l[0],target,key_prob)

    # fit(key_prob)

    master_key = ["00" for x in range(len(target)/2)]
    """HERE COMES MASTER KEY"""
    master_key[0] = '66' #
    master_key[1] = '39' #
    master_key[2] = '6e' #
    master_key[3] = '89'
    master_key[4] = 'c9' #
    master_key[5] = 'db'
    master_key[6] = 'd8'
    master_key[7] = 'cc'
    master_key[8] = '98'
    master_key[9] = '74'
    master_key[10] = '35'
    master_key[11] = '2a'
    master_key[12] = 'cd'
    master_key[13] = '63'
    master_key[14] = '95'
    master_key[15] = '10'
    master_key[16] = '2e'
    master_key[17] = 'af'
    master_key[18] = 'ce'
    master_key[19] = '78'
    master_key[20] = 'aa'
    master_key[21] = '7f'
    master_key[22] = 'ed'
    master_key[23] = '28'
    master_key[24] = 'a0'
    master_key[25] = '7f'
    master_key[26] = '6b'
    master_key[27] = 'c9'
    master_key[28] = '8d'
    master_key[29] = '29'
    master_key[30] = 'c5'
    master_key[31] = '0b'
    master_key[32] = '69'
    master_key[33] = 'b0'
    master_key[34] = '33'
    master_key[35] = '9a'
    master_key[36] = '19'
    master_key[37] = 'f8'
    master_key[38] = 'aa'
    master_key[39] = '40'
    master_key[40] = '1a'
    master_key[41] = '9c'
    master_key[42] = '6d'
    master_key[43] = '70'
    master_key[44] = '8f'
    master_key[45] = '80'
    master_key[46] = 'c0'
    master_key[47] = '66'
    master_key[48] = 'c7'
    master_key[49] = '63'
    master_key[50] = 'fe'
    master_key[51] = 'f0'
    master_key[52] = '12'
    master_key[53] = '31'
    master_key[54] = '48'
    master_key[55] = 'cd'
    master_key[56] = 'd8'
    master_key[57] = 'e8'
    master_key[58] = '02'
    master_key[59] = 'd0'
    master_key[60] = '5b'
    master_key[61] = 'a9'
    master_key[62] = '87'
    master_key[63] = '77'
    master_key[64] = '33'
    master_key[65] = '5d'
    master_key[66] = 'ae'
    master_key[67] = 'fc'
    master_key[68] = 'ec'
    master_key[69] = 'd5'
    master_key[70] = '9c'
    master_key[71] = '43'
    master_key[72] = '3a'
    master_key[73] = '6b'
    master_key[74] = '26'
    master_key[75] = '8b'
    master_key[76] = '60'
    master_key[77] = 'bf'
    master_key[78] = '4e'
    master_key[79] = 'f0'
    master_key[80] = '3c'
    master_key[81] = '9a'
    master_key[82] = '61'

    decrypt_messages(l, master_key)