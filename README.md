# senior-project-spring-2022-encryption-project
senior-project-spring-2022-encryption-project created by GitHub Classroom

Author: Nhat Quang Dinh 

Resource: codemy.com

Project name: SAFSS ( Software Applications for Security Study)

* Service 1: Password generators

Function: Password will be generate base on how long user want it to be. Password will be the combination of Lower case, Upper case, digits and punctuation. This set up is default. 

* Service 2: Password Check 

function: This funcion will check user passwork strength. The method of grading base on Length, number character of lower case, number character of upper case, number character of punctuation. If the length of input password is lower than 8, check process will be finish and result will be "Very weak" and score will be zerowith no exception. If the length greater than 8, the checking process will continue. After checking, the input password will be scored. Base on the score, It will be evaluate base on belove system:

<13 => strength = medium

<16 => strength = strong

>=17 => strength = excellent 

* Service 3: Ceaser Cipher 

Function: This funtion will encryt the text, message and files as demand. With files encrypt, the encrypted file will be download to user computer. the location of encrypted file will in This PC > Document. 

library use: 

from tkinter import *

from tkinter import ttk

from random import randint

import string
