# Danny Dinh
# senior project
# encryption Project
#SAFSS - Software Applications for Security Study


import random
import re
import string
from tkinter import *
from tkinter import messagebox
from tkinter import filedialog
from tkinter import ttk

import clipboard as clipboard
import pybase64
from cryptography.fernet import Fernet
from tkinter.filedialog import asksaveasfile
from tkinter.filedialog import askopenfile

from sqlalchemy import column

root = Tk()
root.title("SAFSS")
root.geometry("700x600")

mytab = ttk.Notebook(root)
mytab.pack()

global selected
selected = False
# tab creation
passTab = Frame(mytab, width=600, height=500)
checkTab = Frame(mytab, width=600, height=500)
cipherTab = Frame(mytab, width=600, height=500)
text_cipher = Frame(mytab, width=600, height=500)

# tab add to the App
passTab.pack(fill="both", expand=1)
checkTab.pack(fill="both", expand=1)
cipherTab.pack(fill="both", expand=1)
text_cipher.pack(fill="both", expand=1)

mytab.add(passTab, text="Password Generator")
mytab.add(checkTab, text="Password Check")
mytab.add(cipherTab, text="Caesar Cipher")
mytab.add(text_cipher, text="Text_E&D")

# --------------------------------------------------------------------
# Passsword Generator

# Generate random password
def newRand():
    # clear entry box
    O_box.delete(0, END)
    valid_box.delete(1.0, END)
    
    pw_len = int(E_box.get())
    characters = string.ascii_lowercase + string.ascii_uppercase + string.digits + string.punctuation
    your_password = ''
    # for x in range(pw_len):
        # your_password += chr(randint(33, 126))
    your_password = ''.join(random.choice(characters) for x in range(pw_len))
    O_box.insert(0, your_password)
    
    # check if password is valid
    flag = 0
    valid_msg = 'Explanation: \n'
    OUTPUT = 'OUTPUT: \n'
    regex = re.compile('[@_!#$%^&*()<>?/\|}{~:]')
    valid_box.delete("1.0", END)
    while True:
        if len(your_password) < 8:
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
        
# The command will be printed and can not be edited
    valid_box.insert("1.0", OUTPUT)
    valid_box.insert("1.0", valid_msg)
    # valid_box.configure(state=DISABLED)

# save password for Text Caesar
def Save_pass():
    pass_file = open("Vault.txt", 'a')
    pass_file.writelines(O_box.get() + "\n")
    messagebox.showinfo(message="Your password is saved and ready to use", title="Password saved!")

def Del_pass():
    try:
        pas_rm = O_box.get()
        file = open("Vault.txt", "r")
        lines = file.readlines()
        file.close()
        
        new_file = open("Vault.txt", "w")
        for line in lines:
            if line.strip("\n") != pas_rm:
                 new_file.write(line)
        new_file.close()

        messagebox.showinfo(message="Successfully remove")
    except:
        messagebox.showinfo(message="The password you want to delete is not in the file")
# Copy function
def clipper():
    # clear clipboard
    root.clipboard_clear()
    
    #copy clipboard
    root.clipboard_append(O_box.get())
    
    

# Cut function (Error)
def cut_text():
    global selected
    if O_box.selection_get():
    
    #grab selected text from text box
        selected = O_box.selection_get()
    #delete selected text from text Box
        O_box.delete("sel.first", "sel.last")
        root.clipboard_clear()
        root.clipboard_append(selected)
frame = LabelFrame (passTab, text ="Enter how long you want your password to be: ")
frame.pack(pady=5)

# Entry box
E_box = Entry(frame, font=("helvetica", 24))
E_box.pack(pady=10, padx=10)

# Output box
O_box = Entry(passTab, text='', font=("helvetica", 24))
O_box.pack(pady=20, padx=20)

# create frame for button and button
f_button = Frame(passTab)
f_button.pack(pady=10)

g_button = Button(f_button, text="Generate Password", command=newRand)
g_button.grid(row=0, column=0, padx=10)

clip_but = Button(f_button, text="Copy", command=clipper)
clip_but.grid(row=0, column=1, padx=10)

cut_but = Button(f_button, text="Cut", command=cut_text)
cut_but.grid(row=0, column=2, padx=10)

save_but = Button(f_button, text="Save for encryption/decryption", command=Save_pass)
save_but.grid(row=0, column=3, padx=10)

del_but = Button(f_button, text="remove from encryption/decryption", command=Del_pass)
del_but.grid(row=0, column=4, padx=10)
# paste_text = Button(f_button, text="Paste", command=paste_text)
# paste_text.grid(row=0, column=3, padx=20)

# create frame for readOnly Box
valid_frame = LabelFrame(passTab, text="Validation")
valid_frame.pack(pady=10)

valid_box = Text(valid_frame, font=("helvetica", 16), height=10)
valid_box.pack(pady=10, padx=10)

# --------------------------------------------------------------------


# --------------------------------------------------------------------
# Password Strength Checker

def check_password():
    
    result_box.delete(1.0,END)
    pass_test = str(ET_box.get("1.0", 'end-1c'))
    
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
    
# check password length
    if len(pass_test) < 8:
        score = 0
        result_box.insert("1.0", "Your password is too short \n")
    else:
        score += 1
       

# check character in password
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
        else:  # check special character
            specials += 1
            
    score = specials + upperchar + lowerchar + digits
# Printing Analysis Result
    msg = "Lowercase character: " + str(lowerchar) + "\n"
    result_box.insert("1.0", msg)
    msg1 = "Uppercase character: " + str(upperchar) + "\n"
    result_box.insert("1.0",msg1)
    msg2 = "Digits character: " + str(digits) + "\n"
    result_box.insert("1.0", msg2)
    msg3 = "Specials character: " + str(specials) + "\n"
    result_box.insert("1.0", msg3)
    msg4 = "Score: " + str(score) + "\n"
    result_box.insert("1.0", msg4)
    
# Grading Password strength
    if score < 9:
        result_box.insert("1.0", "Password strength: Weak\n" )
    elif score < 13:
        result_box.insert( "1.0","Password strength: Medium\n" )
    elif score < 16:
        result_box.insert("1.0", "Password strength: Strong\n")
    elif score >= 17:
        result_box.insert("1.0", "Password strength: Excellent\n")
# Enter Box
check_f = LabelFrame(checkTab, text = "Check your password strength")
check_f.pack(pady=5)

ET_box = Text(check_f, height=5, width=100, font=("helvetica", 18))
ET_box.pack(pady=10, padx=10)

# check Button and frame
check_f1 = Frame(checkTab)
check_f1.pack(pady=10)


Check_but = Button(check_f1, text="Check Strength", command=check_password)
Check_but.grid(row=0, column=1, padx=10)

# result box
result_F = LabelFrame(checkTab, text="Result")
result_F.pack(pady=5)

result_box = Text(result_F, height=10, width=100, font=("helvetica", 16))
result_box.pack(pady=10, padx=10)
# --------------------------------------------------------------------


# --------------------------------------------------------------------
# Ceaser Cipper
# Generate key
def generate_key():
    key = Fernet.generate_key()
    Key_entry.insert(END, key)
    
    with open('file_key.key', 'w') as F_key:
        F_key.write(key.decode("utf-8"))
        F_key.close()

# class encryption
def Encryption():
    # Alert when key is not include:
    if Key_entry.get() == "":
        messagebox.showwarning("Need Key code", "If you don't have key, generate one and it will save as key file")
    else:
        K_entry = Key_entry.get()
        if isinstance(K_entry,bytes) == False:
            K_entry.encode('utf-8")')
            
    secret = ET_box2.get(1.0, END)
    secret = bytes(secret, 'utf-8')
    # clear the Box
    ET_box2.delete(1.0, END)

    # and load generated key
    
    fernet = Fernet(K_entry)
    
    secret = fernet.encrypt(secret)
    
    ET_box2.insert(END, secret.decode('utf-8'))
    
# class decryption
def Decryption():
    # Alert when key is not include:
    if Key_entry.get() == "":
        messagebox.showwarning("Need Key code", "You must have key file and must be the same one as use as encrypting !!!")
    else:
        K_entry = Key_entry.get()
        if isinstance(K_entry,bytes) == False:
            K_entry.encode('utf-8")')

        secret = ET_box2.get(1.0, END)
        secret = bytes(secret, 'utf-8')
        # clear the Box
        ET_box2.delete(1.0, END)

        # and load generated key

        fernet = Fernet(K_entry)

        secret = fernet.decrypt(secret)

        ET_box2.insert(END, secret.decode('utf-8'))
        

# Save text
def Save_text():
    f = filedialog.asksaveasfilename(defaultextension=".*", title="Save File", filetypes=(('Text Files', '*.txt'), ("Other files", "*.*")))
    if f:
        tf = open(f, 'w')
        tf.write(ET_box2.get(1.0, END))
        tf.close()
# open file and display
def open_file():
    
    f = filedialog.askopenfilename(filetypes=(('Text File', '*.txt'), ('All Files', '*.*')))
    f = open(f, 'r')
    content = f.read()
    ET_box2.insert(END, content)
    f.close()

# open key file and read to make sure the key is there
def open_key_file():
    f = filedialog.askopenfilename(filetypes=(('Text File', '*.txt'), ('Key File', '*.key'), ('All Files', '*.*')))
    f = open(f, 'r')
    content = f.read()
    Key_entry.insert(END, content)
    f.close()
    


# checkbox function
def check_code():
    if Key_entry.cget('show') == '*':
        Key_entry.config(show='')
    else:
        Key_entry.config(show='*')
# 2 box ask for input file
input_text_F = Frame(cipherTab)
input_text_F.pack(pady=2)

open_file = Button(input_text_F, text="File for Encryption/Decryption", command=open_file)
open_file.grid(column=0, row=1, sticky='w', padx=5, pady=5)

open_key = Button(input_text_F, text="Key File", command=open_key_file)
open_key.grid(column=1, row=1, sticky='w', padx=5, pady=2)

# key text box
key_frame = LabelFrame(cipherTab, text="Key")
key_frame.pack(pady=20)

Key_entry = Entry(key_frame, font=("helvetica", 18), width=50, show="*")
Key_entry.grid(pady=4, padx=4)

hide_check = Checkbutton(cipherTab, text="Check Key", command=check_code)
hide_check.place(x=17, y=120)
# adding path showing box
# pathh = Entry(cipherTab)
# pathh.pack(expand=True, fill=X, padx=2)

# Create entry text box
E_frame = LabelFrame(cipherTab, text="Input File Content")
E_frame.pack(pady=5)

ET_box2 = Text(E_frame, height=12, width=54,  font=("helvetica", 16))
ET_box2.pack(pady=6, padx=5)



# Encryption Button
EB_frame = Frame(cipherTab)
EB_frame.pack(pady=5)

Encrypt_But = Button(EB_frame, text="Encrypt", command=Encryption)
Encrypt_But.grid(row=0, column=0, padx=10)
# Decryption Button
DB_frame = Frame(cipherTab)
DB_frame.pack(pady=5)

Decrypt_But = Button(EB_frame, text="Decrypt", command=Decryption)
Decrypt_But.grid(row=0, column=1, padx=10)
# Result Box for decode and encode
# Rframe = LabelFrame(cipherTab, text="Output")
# Rframe.pack(pady=5)
#
# result_box2 = Text(Rframe, height=10, width=100, font=("helvetica", 16))
# result_box2.pack(pady=10, padx=10)


# Save feature
save_but = Button(EB_frame, text="Save as", command=Save_text)
save_but.grid(row=0, column=2, padx=10)

# Generate random key
gen_key = Button(EB_frame, text="Generate key", command=generate_key)
gen_key.grid(row=0, column=3, padx=10)
# --------------------------------------------------------------------

# --------------------------------------------------------------------
# Encrypted decrypted text by password

def clear():
    #clear everything
    P_text_box.delete(1.0, END)
    pass_entry.delete(0, END)
    
def Encrypted_text():
    # get text
    secret = P_text_box.get(1.0, END)
    
    # clear the Box
    P_text_box.delete(1.0, END)
    
    # logic for password
    file = open("Vault.txt", "r")
    content = file.read()

    if pass_entry.get() in content:
        # convert bytes
        secret = secret.encode("ascii")
        # convert to base64
        secret = pybase64.b64encode(secret)
        # convert back to ascii
        secret = secret.decode("ascii")
        # print to textbox
        P_text_box.insert(END, secret)
    else:
    # wrong password alert
        messagebox.showwarning("Incorrect Password", "Wrong Password, Try Again!")

def Decryption_text():
    # get text
    secret = P_text_box.get(1.0, END)
    
    # clear the Box
    P_text_box.delete(1.0, END)
    
    # logic for password
    file = open("Vault.txt", "r")
    content = file.read()
    
    if pass_entry.get() in content:
        # convert bytes
        secret = secret.encode("ascii")
        # convert to base64
        secret = pybase64.b64decode(secret)
        # convert back to ascii
        secret = secret.decode("ascii")
        # print to textbox
        P_text_box.insert(END, secret)
    else:
        # wrong password alert
        messagebox.showwarning("Incorrect Password", "Wrong Password, Try Again!")

def paste_fun():
    pass_entry.delete(0, END)
    a = root.clipboard_get()
    pass_entry.insert(0, a)
# Textbox for encryption/decryption
en_pack = Label(text_cipher, text="Encrypt/Decrypt Text", font=("helvetica", 14))
en_pack.pack(pady=10)

# text box for plaintext entry
P_text_box = Text(text_cipher, width=70, height=10)
P_text_box.pack(pady=10)


# ask input is password that will be generated into a key
pass_pack = Label(text_cipher, text="Enter your password: ", font=("helvetica", 14))
pass_pack.pack()

# text box for password entry
# show star for hidden password
pass_entry = Entry(text_cipher, font=("helvetica", 18), width=43, show="*")
pass_entry.pack(pady=10)


F_button = Frame(text_cipher)
F_button.pack(pady=10)
# Button features
en_button = Button(F_button, text="Encrypt", font=("helvetica", 18), command=Encrypted_text)
en_button.grid(row=0, column=0)

De_button = Button(F_button, text="Decrypt", font=("helvetica", 18), command=Decryption_text)
De_button.grid(row=0, column=1, padx=10)

cl_button = Button(F_button, text="Clear", font=("helvetica", 18), command=clear)
cl_button.grid(row=0, column=2)

pas_button = Button(F_button, text="Paste Password", font=("helvetica", 18), command=paste_fun)
pas_button.grid(row=0, column=3, padx=10)
# --------------------------------------------------------------------



root.mainloop()