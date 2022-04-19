# Danny Dinh
# senior project
# encryption Project
#SAFSS - Software Applications for Security Study


from tkinter import *
from tkinter import ttk
from random import randint
import string
import random
import re
from cryptography.fernet import Fernet
import base64




root = Tk()
root.title("SAFSS")
root.geometry("600x500")

mytab = ttk.Notebook(root)
mytab.pack()

global selected
selected = False
#tab creation
passTab = Frame(mytab, width=500, height=400)
checkTab = Frame(mytab, width=500, height=400)
cipherTab = Frame(mytab, width=500, height=400)
text_cipher = Frame(mytab, width=500, height=400)

#tab add to the App
passTab.pack(fill="both", expand=1)
checkTab.pack(fill="both", expand=1)
cipherTab.pack(fill="both", expand=1)
text_cipher.pack(fill="both", expand=1)

mytab.add(passTab, text="Password Generator")
mytab.add(checkTab, text="Password Check")
mytab.add(cipherTab, text="Caesar Cipher")
mytab.add(text_cipher, text="Text_E&D")
######################################################################
#Passsword Generator

#Generate random password
def newRand():
    #clear entry box
    O_box.delete(0, END)
    
    pw_len = int(E_box.get())
    characters = string.ascii_lowercase + string.ascii_uppercase + string.digits + string.punctuation
    your_password = ''
    # for x in range(pw_len):
        # your_password += chr(randint(33, 126))
    your_password = ''.join(random.choice(characters) for x in range(pw_len))
    O_box.insert(0, your_password)
    
    #check if password is valid
    flag = 0
    valid_msg = 'Explanation: \n'
    OUTPUT = 'OUTPUT: \n'
    regex = re.compile( '[@_!#$%^&*()<>?/\|}{~:]' )
    valid_box.delete("1.0", END)
    while True:
        if (len(your_password)<8):
            flag = -1
            valid_msg += "Length needs to be greater than 8.\n"
            break
        elif not re.search("[a-z]", your_password):
            flag = -1
            valid_msg += "Lack of Lowercase.\n"
            break
        elif not re.search("[A-Z]", your_password):
            flag = -1
            valid_msg += "Lack of uppercase.\n"
            break
        elif not re.search("[0-9]", your_password):
            flag = -1
            valid_msg += "lack of Digits.\n"
            break
        elif not regex.search(your_password):
            flag = -1
            valid_msg += "lack of Punctuation.\n"
            break
        # elif re.search("\s", your_password):
        #     flag = -1
        #     break
        else:
            flag = 0
            OUTPUT += "Valid Password\n"
            break

    if flag == -1:
        OUTPUT += "Not a Valid Password\n"
        
#The command will be printed and can not be edited
    valid_box.insert("1.0", OUTPUT)
    valid_box.insert("1.0", valid_msg)
    valid_box.configure(state=DISABLED)
    
#Copy function
def clipper():
    #clear clipboard
    root.clipboard_clear()
    
    #copy clipboard
    root.clipboard_append(O_box.get())
    
# #Paste function (Error)
# def paste_text():
#     if selected:
#         positions = O_box.index(INSERT)
#         O_box.insert(positions, selected)

#Cut function (Error)
def cut_text():
    global selected
    if O_box.selection_get():
    
    #grab selected text from text box
        selected = O_box.selection_get()
    #delete selected text from text Box
        O_box.delete("sel.first", "sel.last")
        
frame = LabelFrame (passTab, text ="Enter how long you want your password to be: ")
frame.pack(pady=5)

#Entry box
E_box = Entry(frame, font=("helvetica", 24))
E_box.pack(pady=10, padx=10)

#Output box
O_box = Entry(passTab, text='', font=("helvetica", 24))
O_box.pack(pady=20, padx=20)

#create frame for button and button
f_button = Frame(passTab)
f_button.pack(pady=20)

g_button = Button(f_button, text="Generate Password", command=newRand)
g_button.grid(row=0, column=0, padx=20)

clip_but = Button(f_button, text="Copy", command=clipper)
clip_but.grid(row=0, column=1, padx=20)

cut_but = Button(f_button, text="Cut", command=cut_text)
cut_but.grid(row=0, column=2, padx=20)

# paste_text = Button(f_button, text="Paste", command=paste_text)
# paste_text.grid(row=0, column=3, padx=20)

#creat frame for readOnly Box
valid_frame = Frame(passTab)
valid_frame.pack(pady=10)

valid_box = Text(valid_frame, font=("helvetica", 18))
valid_box.pack(pady=10, padx=10)

######################################################################


######################################################################
#Password Strength Checker

def check_password():
    
    pass_test = str(ET_box.get("1.0",'end-1c'))
    
    score = 0

# check if the password is common
    with open('rockyou.txt', 'r', errors='ignore') as f:
        common_pass = f.read().splitlines()
    if pass_test in common_pass:
        result_box.insert("1.0", "Your password complexity: common \nStrength: very weak \n")
        score = 0
        msg_fail = "Score: " + str( score ) + "\n"
        result_box.insert("1.0", msg_fail)
        return
    else:
        pass
    
#check password length
    if len(pass_test) >= 8:
        score += 1
    else:
        score += 0
        result_box.insert("1.0", "Your password is too short \n")
       

#check character in password
    upperchar = 0
    lowerchar = 0
    digits = 0
    specials = 0
    for c in pass_test:
        if c in string.ascii_lowercase: # check lowercase character
            lowerchar += 1
        elif c in string.ascii_uppercase: # check uppercase character
            upperchar += 1
        elif c in string.digits: # check digits character
            digits += 1
        else: #check special character
            specials += 1
            
    score = specials + upperchar + lowerchar + digits
#Printing Analysis Result
    msg = "Lowercase character: " + str(lowerchar) + "\n"
    result_box.insert("1.0",msg)
    msg1 = "Uppercase character: " + str(upperchar) + "\n"
    result_box.insert("1.0",msg1)
    msg2 = "Digits character: " + str(digits) + "\n"
    result_box.insert("1.0", msg2)
    msg3 = "Specials character: " + str(specials) + "\n"
    result_box.insert("1.0", msg3)
    msg4 = "Score: " + str(score) + "\n"
    result_box.insert("1.0", msg4)
    
#Grading Password strength
    if score < 13:
        result_box.insert("1.0","Password strength: Medium\n")
    elif score < 9:
        result_box.insert("1.0", "Password strength: Weak\n")
    elif score < 16:
        result_box.insert("1.0", "Password strength: Strong\n")
    elif score >= 17:
        result_box.insert("1.0", "Password strength: Excellent\n")
#Enter Box
check_f = LabelFrame(checkTab, text = "Check your password strength")
check_f.pack(pady=5)

ET_box = Text(check_f, height=5, width=100, font=("helvetica", 18))
ET_box.pack(pady=10,padx=10)

#check Button and frame
check_f1 = Frame(checkTab)
check_f1.pack(pady=10)


Check_but = Button(check_f1, text="Check Strength", command=check_password)
Check_but.grid(row=0, column=1, padx=10)

#result box
result_F = LabelFrame(checkTab, text="Result")
result_F.pack(pady=5)

result_box = Text(result_F, height=5, width=100, font=("helvetica", 16))
result_box.pack(pady=10, padx=10)
######################################################################


######################################################################
#Ceaser Cipper

#class encryption
def Encryption():
    encryp_text = ""
    
    #generate key
    key = Fernet.generate_key()

    result_box2.insert(END, str(key) + "\n")
    
    with open('file_key.key', 'wb') as F_key:
        F_key.write(key)
    F_key.close()
    # crate instance of Fernet
    # and load generated key
    
    fernet = Fernet(key)
    
    with open('file.txt', 'rb') as content:
        data = content.read()
        
    encryp_text = fernet.encrypt(data)
    
    with open ('file_encrypt.txt','wb') as f:
        f.write(encryp_text)
        
    # plaintext = str(ET_box2.get("1.0", 'end-1c'))
    # plaintext_bytes = plaintext.enccode()
    #encryp_text = fernet.encrypt(plaintext)
    
    # for c in plaintext:
    #     if c.isupper():
    #         c_index = ord(c) - ord('A')
    #         # shift the current character by key positions
    #         c_shifted = (c_index + key) % 26 + ord('A')
    #         c_new = chr(c_shifted)
    #
    #         encryp_text += c_new
    #     elif c.islower():
    #         c_index = ord(c) - ord('a')
    #         # shift the current character by key positions
    #         c_shifted = (c_index + key) % 26 + ord('a')
    #         c_new = chr(c_shifted)
    #         encryp_text += c_new
    #
    #     elif c.isdigit():
    #         c_new = (int(c) + key) % 10
    #         encryp_text += str(c_new)
    #
    #     else:
    #         encryp_text += c
            
    result_box2.insert(END, encryp_text)
#class decryption
def Decrytption():
    decrypt_text = ""

    # generate key
    key = Fernet.generate_key()

    result_box2.insert(END, str(key) + "\n")

    with open( 'file_key.key', 'rb' ) as F_key:
        F_key.write(key)
    F_key.close()
    # crate instance of Fernet
    # and load generated key

    fernet = Fernet(key)

    with open('file.txt','rb') as content:
        data = content.read()

    encryp_text = fernet.decrypt( data )

    with open( 'file_encrypt.txt', 'wb') as f:
        f.write(decrypt_text)
    # key = 10
    # plaintext = str(ET_box2.get("1.0", 'end-1c'))
    #
    # for c in plaintext:
    #     if c.isupper():
    #         c_index = ord( c ) - ord('A')
    #         # shift the current character by key positions
    #         c_ogrin = (c_index - key) % 26 + ord('A')
    #         c_old = chr(c_ogrin)
    #         decrypt_text += c_old
    #     elif c.islower():
    #         c_index = ord(c) - ord( 'a' )
    #         # shift the current character by key positions
    #         c_ogrin = (c_index - key) % 26 + ord('a')
    #         c_old = chr(c_ogrin)
    #         decrypt_text += c_old
    #     elif c.isdigit():
    #         c_new = (int(c) + key) % 10
    #         decrypt_text += str(c_old)
    #     else:
    #         decrypt_text += c

    result_box2.insert(END, decrypt_text)
#Create entry text box
E_frame = LabelFrame(cipherTab, text="Input")
E_frame.pack(pady=5)

ET_box2 = Text(E_frame, height=10, width=100,  font=("helvetica", 16))
ET_box2.pack(pady=15, padx=15)

#Encryption Button
EB_frame = Frame(cipherTab)
EB_frame.pack(pady=5)

Encrypt_But = Button(EB_frame, text="Encrypt", command=Encryption)
Encrypt_But.grid(row=0, column=0, padx=10)
#Decrytption Button
DB_frame = Frame(cipherTab)
DB_frame.pack(pady=5)

Decrypt_But = Button(EB_frame, text="Decrypt", command=Decrytption)
Decrypt_But.grid(row=0, column=1, padx=10)
#Result Box for decode and encode
Rframe = LabelFrame(cipherTab, text="Output")
Rframe.pack(pady=5)

result_box2 = Text(Rframe, height=10, width=100, font=("helvetica", 16))
result_box2.pack(pady=10, padx=10)

######################################################################

######################################################################
#Encrypted decrypted text by password
def clear():
    pass

def Encrypted_text():
    pass

def Decryption_text():
    pass

#ask input is password that will be generated into a key
Y_key =

en_button = Button(text_cipher, text="Encrypt", font=("helvetica",18), command=Encrypted_text())

De_button = Button(text_cipher, text="Encrypt", font=("helvetica",18), command=Decryption_text())

cl_button = Button(text_cipher, text="Encrypt", font=("helvetica",18), command=clear())
######################################################################



root.mainloop()