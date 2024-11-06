import copy

class S_AES:
    S = [
        [9, 4, 10, 11],
        [13, 1, 8, 5],
        [6, 2, 0, 3],
        [12, 14, 15, 7]
    ]
    IS = [
        [10, 5, 9, 11],
        [1, 7, 8, 15],
        [6, 0, 2, 3],
        [12, 4, 13, 14]
    ]

    def __init__(self,cipher):
        if len(cipher) != 16 or any(c not in '01' for c in cipher):
            raise ValueError("密钥必须是16位的二进制字符串")
        self.cipher = [cipher[:8],cipher[8:16]]
        self.w_0_1 = 0
        self.w_2_3 = 0
        self.w_4_5 = 0
        self.plaintext = [
            ['0000', '0000'],
            ['0000', '0000']
        ]
        self.ciphertext = [
            ['0000', '0000'],
            ['0000', '0000']
        ]
        self.key_generation()

    def get_plaintext(self,plaintext):
        if len(plaintext)!=16 or type(plaintext)!=str:
            print('明文错误')
            return
        self.plaintext[0][0] = plaintext[:4]
        self.plaintext[1][0] = plaintext[4:8]
        self.plaintext[0][1] = plaintext[8:12]
        self.plaintext[1][1] = plaintext[12:]

    def get_ciphertext(self,ciphertext):
        if len(ciphertext)!=16 or type(ciphertext)!=str:
            print('明文错误')
            return
        self.ciphertext[0][0] = ciphertext[:4]
        self.ciphertext[1][0] = ciphertext[4:8]
        self.ciphertext[0][1] = ciphertext[8:12]
        self.ciphertext[1][1] = ciphertext[12:]

    def addroundkey(self,old_first_parameter, old_cipher):
        first_parameter=copy.deepcopy(old_first_parameter)
        cipher=copy.deepcopy(old_cipher)
        intermediate_variable_1=self.xor(first_parameter[0][0]+first_parameter[1][0],cipher[0])
        intermediate_variable_2=self.xor(first_parameter[0][1]+first_parameter[1][1],cipher[1])
        output=[
            [intermediate_variable_1[:4],intermediate_variable_2[:4]],
            [intermediate_variable_1[4:],intermediate_variable_2[4:]]
        ]
        return output

    def s_box(self,string_l,string_u,method):
        int_l=self.binary2decimal(string_l)
        int_u=self.binary2decimal(string_u)
        return self.decimal2binary(method[int_l][int_u])

    def NS(self,old_first_parameter):
        first_parameter=copy.deepcopy(old_first_parameter)
        first_parameter[0][0]=self.s_box(first_parameter[0][0][:2],first_parameter[0][0][2:],self.S)
        first_parameter[1][0]=self.s_box(first_parameter[1][0][:2],first_parameter[1][0][2:],self.S)
        first_parameter[0][1]=self.s_box(first_parameter[0][1][:2],first_parameter[0][1][2:],self.S)
        first_parameter[1][1]=self.s_box(first_parameter[1][1][:2],first_parameter[1][1][2:],self.S)
        return first_parameter

    def INS(self,old_first_parameter):
        first_parameter = copy.deepcopy(old_first_parameter)
        first_parameter[0][0] = self.s_box(first_parameter[0][0][:2], first_parameter[0][0][2:], self.IS)
        first_parameter[1][0] = self.s_box(first_parameter[1][0][:2], first_parameter[1][0][2:], self.IS)
        first_parameter[0][1] = self.s_box(first_parameter[0][1][:2], first_parameter[0][1][2:], self.IS)
        first_parameter[1][1] = self.s_box(first_parameter[1][1][:2], first_parameter[1][1][2:], self.IS)
        return first_parameter

    def SR(self,old_first_parameter):
        first_parameter = copy.deepcopy(old_first_parameter)
        first_parameter[1][0], first_parameter[1][1] = first_parameter[1][1], first_parameter[1][0]
        return first_parameter

    def MC(self,old_first_parameter):
        first_parameter = copy.deepcopy(old_first_parameter)
        first_parameter[0][0] =self.sum(first_parameter[0][0],self.product('0100',first_parameter[1][0]))
        first_parameter[1][0] =self.sum(self.product('0100',first_parameter[0][0]),first_parameter[1][0])
        first_parameter[0][1] =self.sum(first_parameter[0][1],self.product('0100',first_parameter[1][1]))
        first_parameter[1][1] =self.sum(self.product('0100',first_parameter[0][1]),first_parameter[1][1])
        return first_parameter

    def IMC(self,old_first_parameter):
        first_parameter = copy.deepcopy(old_first_parameter)
        first_parameter[0][0] =self.sum(self.product('1001',first_parameter[0][0]),self.product('0010',first_parameter[1][0]))
        first_parameter[1][0] =self.sum(self.product('0010',first_parameter[0][0]),self.product('1001',first_parameter[1][0]))
        first_parameter[0][1] =self.sum(self.product('1001',first_parameter[0][1]),self.product('0010',first_parameter[1][1]))
        first_parameter[1][1] =self.sum(self.product('0010',first_parameter[0][1]),self.product('1001',first_parameter[1][1]))
        return first_parameter

    def gf2_add(self,x1, x2):
        """GF(2^4) addition (XOR operation)"""
        # 将字符串转换为整数
        num1 = int(x1, 2)
        num2 = int(x2, 2)
        return bin(num1 ^ num2)[2:].zfill(4)  # 进行异或并返回4位的二进制字符串

    def gf2_multiply(self,x1, x2):
        """GF(2^4) multiplication modulo x^4 + x + 1"""
        # 将字符串转换为整数
        num1 = int(x1, 2)
        num2 = int(x2, 2)

        # 乘法结果初始化
        result = 0
        # 使用位移和加法进行乘法运算
        for i in range(4):  # 由于GF(2^4)，只需迭代4次
            if (num2 & (1 << i)) != 0:  # 检查num2的第i位是否为1
                result ^= (num1 << i)  # 乘以num1并位移
        # 模除以x^4 + x + 1
        modulus = 0b10011  # x^4 + x + 1的二进制表示
        for i in range(3, -1, -1):  # 从高位到低位检查
            if (result & (1 << (i + 4))) != 0:  # 如果结果的高位为1
                result ^= (modulus << i)  # 模减去模数
        return bin(result)[2:].zfill(4)  # 返回4位的二进制字符串

    def sum(self,x1, x2):
        """Addition in GF(2^4)"""
        return self.gf2_add(x1, x2)

    def product(self,x1, x2):
        """Multiplication in GF(2^4)"""
        return self.gf2_multiply(x1, x2)

    def key_expansion(self,old_cipher):
        cipher=copy.deepcopy(old_cipher)
        w0=cipher[0]
        w1=cipher[1]
        w2=self.xor(w0,self.xor('10000000',self.subnib(self.rotnib(w1))))
        w3=self.xor(w2,w1)
        w4=self.xor(w2,self.xor('00110000',self.subnib(self.rotnib(w3))))
        w5=self.xor(w4,w3)
        return [w2,w3], [w4,w5]

    def subnib(self,x):
        return self.s_box(x[:2],x[2:4],self.S)+self.s_box(x[4:6],x[6:],self.S)

    def rotnib(self,x):
        return x[4:]+x[:4]

    def xor(self,string1,string2):
        result=''
        for i in range(len(string1)):
            if string1[i]!=string2[i]:
                result+='1'
            else:
                result+='0'
        return result

    def binary2decimal(self,binary):
        decimal=0
        for i in binary:
            decimal*=2
            decimal+=int(i)
        return decimal

    def decimal2binary(self, decimal):
        return f"{decimal:04b}"

    #密钥生成
    def key_generation(self):
        w_0_1=self.cipher
        w_2_3,w_4_5=self.key_expansion(self.cipher)
        self.w_0_1,self.w_2_3,self.w_4_5=w_0_1,w_2_3,w_4_5

    def first_round_encryption(self,old_first_parameter,old_w_2_3):
        first_parameter=copy.deepcopy(old_first_parameter)
        w_2_3=copy.deepcopy(old_w_2_3)
        intermediate_variable_1=self.NS(first_parameter)
        intermediate_variable_2=self.SR(intermediate_variable_1)
        intermediate_variable_3=self.MC(intermediate_variable_2)
        output=self.addroundkey(intermediate_variable_3,w_2_3)
        return output

    def second_round_encryption(self,old_first_parameter,old_w_4_5):
        first_parameter = copy.deepcopy(old_first_parameter)
        w_4_5 = copy.deepcopy(old_w_4_5)
        intermediate_variable_1 = self.NS(first_parameter)
        intermediate_variable_2 = self.SR(intermediate_variable_1)
        output = self.addroundkey(intermediate_variable_2, w_4_5)
        return output

    #加密全过程
    def encrypt_one(self):
        intermediate_variable_1=self.addroundkey(self.plaintext,self.w_0_1)
        intermediate_variable_2=self.first_round_encryption(intermediate_variable_1,self.w_2_3)
        ciphertext=self.second_round_encryption(intermediate_variable_2,self.w_4_5)
        return self.transform_ciphertext_format(ciphertext)

    def double_encrypt_one(self,plaintext,cipher1,cipher2):
        self.get_plaintext(plaintext)
        self.cipher = [cipher1[:8], cipher1[8:]]
        intermediate_variable_1=self.encrypt_one()
        self.get_plaintext(intermediate_variable_1)
        self.cipher = [cipher2[:8], cipher2[8:]]
        return self.encrypt_one()

    def triple_encrypt_one(self,plaintext,cipher1,cipher2,cipher3):
        intermediate_variable_1=self.double_encrypt_one(plaintext,cipher1,cipher2)
        self.get_plaintext(intermediate_variable_1)
        self.cipher = [cipher3[:8], cipher3[8:]]
        return self.encrypt_one()

    def meet_in_the_middle(self,plaintext,ciphertext,plaintext2,ciphertext2):
        intermediate_variable_1= {}
        self.get_plaintext(plaintext)
        self.get_ciphertext(ciphertext)
        for i in range(2**16):
            cipher=bin(i)[2:].zfill(16)
            self.cipher=[cipher[:8],cipher[8:]]
            intermediate_variable_1[cipher]=self.encrypt_one()
        for i in range(2 ** 16):
            cipher = bin(i)[2:].zfill(16)
            self.cipher = [cipher[:8], cipher[8:]]
            if self.decrypt() in intermediate_variable_1.values():
                cipher1=[key for key, value in intermediate_variable_1.items() if value == self.decrypt()][0]
                if self.double_encrypt_one(plaintext2,cipher1,cipher)==ciphertext2:
                    return cipher1,cipher

    def encrypt_more(self,plaintext):
        if len(plaintext)%2==1:
            plaintext+='\0'
        last_ciphertext='0000000000000000'
        ciphertext=''
        for i in range(len(plaintext)//2):
            i_ascll=bin(ord(plaintext[2*i]))[2:].zfill(8)+bin(ord(plaintext[2*i+1]))[2:].zfill(8)
            self.get_plaintext(self.xor(last_ciphertext,i_ascll))
            last_ciphertext=self.encrypt_one()
            ciphertext += chr(int(last_ciphertext[:8], 2))
            ciphertext += chr(int(last_ciphertext[8:], 2))
        return ciphertext

    def encrypt(self,plaintext,mode):
        if mode == "16bit":
            self.get_plaintext(plaintext)
            return self.encrypt_one()
        if mode == "ASCII字符串":
            return self.encrypt_more(plaintext)

    #解密全过程
    def decrypt(self):
        intermediate_variable_1 = self.addroundkey(self.ciphertext,self.w_4_5)
        intermediate_variable_2 = self.first_round_decryption(intermediate_variable_1,self.w_2_3)
        plaintext= self.second_round_decryption(intermediate_variable_2,self.w_0_1)
        return self.transform_ciphertext_format(plaintext)

    def first_round_decryption(self,old_first_parameter,old_w_2_3):
        first_parameter = copy.deepcopy(old_first_parameter)
        w_2_3 = copy.deepcopy(old_w_2_3)
        intermediate_variable_1=self.SR(first_parameter)
        intermediate_variable_2=self.INS(intermediate_variable_1)
        intermediate_variable_3=self.addroundkey(intermediate_variable_2,w_2_3)
        output=self.IMC(intermediate_variable_3)
        return output

    def second_round_decryption(self,old_first_parameter,old_w_0_1):
        first_parameter = copy.deepcopy(old_first_parameter)
        w_0_1 = copy.deepcopy(old_w_0_1)
        intermediate_variable_1=self.SR(first_parameter)
        intermediate_variable_2=self.INS(intermediate_variable_1)
        output=self.addroundkey(intermediate_variable_2,w_0_1)
        return output

    @staticmethod
    def isright(text,length):
        if len(text)==length:
            for i in text:
                if i not in ['1','0']:
                    return False
            return True
        else:
            return False

    @staticmethod
    def is_ASCII_text(text):
        return all(ord(char) < 128 for char in text)

    def transform_ciphertext_format(self,ciphertext):
        return ciphertext[0][0]+ciphertext[1][0]+ciphertext[0][1]+ciphertext[1][1]

if __name__=="__main__":
    test=S_AES('1010101010101010')
    test.get_plaintext('1010101010101010')
    result=test.encrypt_one()
    print(result)
    test.get_ciphertext(result)
    print(test.decrypt())