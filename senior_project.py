# Danny Dinh
# senior project
# encryption Project

from tkinter import *
from random import randint

rot = Tk()
rot.title = "Password Generator"
rot.geometry =(1000,700)

your_password = chr(randint(33,126))

def newRand():
    pass
def clipper():
    pass
frame = LabelFrame (rot, text ="Enter how long you want your password to be: ")
frame.pack(pady=20)

#Entry box
E_box = Entry(frame, font=("helvetica", 24))
E_box.pack(pady=30,padx=20)

#Output box
O_box = Entry(rot,text='', font=("helvetica",24))
O_box.pack(pady=30,padx=20)

#create frame for button and button
f_button = Frame(rot)
f_button.pack(pady=20)

g_button = Button(f_button, text="Generate Password", command=newRand)
g_button.grid(row=0, column=0, padx=20)

clip_but = Button(f_button, text="Copy to clipboard", command=clipper)
clip_but.grid(row=0, column=1, padx=20)

rot.mainloop()