# Danny Dinh
# senior project
# encryption Project
#SAFSS - Software Applications for Security Study


from tkinter import *
from tkinter import ttk
from random import randint
import string




root = Tk()
root.title("SAFSS")
root.geometry("600x500")

mytab = ttk.Notebook(root)
mytab.pack()

#tab creation
passTab = Frame(mytab, width=500, height=400)
checkTab = Frame(mytab, width=500, height=400)
cipherTab = Frame(mytab, width=500, height=400)


#tab add to the App
passTab.pack(fill="both", expand=1)
checkTab.pack(fill="both", expand=1)
cipherTab.pack(fill="both", expand=1)

mytab.add(passTab, text="Password Generator")
mytab.add(checkTab, text="Password Check")
mytab.add(cipherTab, text="Ceaser Cipher")

######################################################################
#Passsword Generator

#Generate random password
def newRand():
    #clear entry box
    O_box.delete(0,END)
    
    pw_len = int(E_box.get())
    
    your_password = ''
    for x in range(pw_len):
        your_password += chr(randint(33,126))
    O_box.insert(0,your_password)
    
#Copy function
def clipper():
    #clear clipboard
    root.clipboard_clear()
    
    #copy clipboard
    root.clipboard_append(O_box.get())

frame = LabelFrame (passTab, text ="Enter how long you want your password to be: ")
frame.pack(pady=20)

#Entry box
E_box = Entry(frame, font=("helvetica", 24))
E_box.pack(pady=30,padx=20)

#Output box
O_box = Entry(passTab,text='', font=("helvetica",24))
O_box.pack(pady=30,padx=20)

#create frame for button and button
f_button = Frame(passTab)
f_button.pack(pady=20)

g_button = Button(f_button, text="Generate Password", command=newRand)
g_button.grid(row=0, column=0, padx=20)

clip_but = Button(f_button, text="Copy", command=clipper)
clip_but.grid(row=0, column=1, padx=20)
######################################################################


######################################################################
#Password check
def check_password():
    
    pass_test = str(ET_box.get("1.0",'end-1c'))
    
    score = 0

# check if the password is common
    with open('rockyou.txt', 'r', errors='ignore') as f:
        common_pass = f.read().splitlines()
    if pass_test in common_pass:
        result_box.insert( "1.0","Your password complexity: common \nStrength: very weak \n" )
        score = 0
    else:
        pass
    
#check password length
    if len(pass_test) >= 8:
        score += 1
    else:
        score += 0
        result_box.insert("1.0","Your password is too short \n")

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
    elif score < 16:
        result_box.insert("1.0", "Password strength: Strong\n")
    elif score >= 17:
        result_box.insert("1.0", "Password strength: Excellent\n")
#Enter Box
ET_box = Text(checkTab,height=5, width=100, font=("helvetica",18))
ET_box.pack(pady=20,padx=20)

#check Button and frame
check_f = Frame(checkTab)
check_f.pack(pady=20)


Check_but = Button(check_f, text="Check Strength", command=check_password)
Check_but.grid(row=0, column=1, padx=20)

#result box
result_F = LabelFrame(checkTab, text="Result")
result_F.pack(pady=20)

result_box = Text(result_F,height=5, width=100, font=("helvetica",16))
result_box.pack(pady=20, padx=20)
######################################################################


######################################################################
#Ceaser Cipper
#Create entry text box
ET_box2 = Entry(cipherTab,width=100,font=("helvetica", 18))
ET_box2.pack(pady=30,padx=30)

#Result Box for decode and encode
result_box2 = Text(cipherTab, width=100,font=("helvetica", 18))
result_box2.pack(pady=20, padx=20)

######################################################################





root.mainloop()