from tkinter import *
from tkinter import messagebox
import random
import secrets
import string

root = Tk()
root.title('Password Generator and Password Checker')



def password_generator(*args, length=8):
	# character_list = [str(i) for i in string.digits] + [i for i in string.ascii_letters] + ['!', '#', '$', '%', '&', '*', '?', '/', '\\', '|', '_']
	# password_list = random.choices(character_list, k=(length-len(args)))
	password_list = []
	for i in range(length-len(args)):
		password_list += chr(random.randint(33, 126))	# much simpler method by calling for ascii indexed characters using 'chr()' function

	for i in args:
		password_list.append(i)
	random.shuffle(password_list)

	password = ''
	for char in password_list:
		password += char

	password_window = Tk()
	password_window.title('Your Password')
	password_generator_label = Label(password_window, text="Your password is: ")
	password_generator_label.grid(row=0, column=0)
	password_generator_entry = Entry(password_window, width=30)
	password_generator_entry.grid(row=0, column=1)
	password_generator_entry.insert(0, str(password))

def password_checker(password, char):
	if char in password:
		messagebox.showinfo('password checker', 'the character is in your password!')
	else:
		messagebox.showerror('password checker', 'the character is not in your password')





def clear_entry_generator_char_req(event):
	if generator_char_req_input.get() == 'what character do you want in your password?' or generator_char_req_input.get() == 'any other required characters?':
		generator_char_req_input.delete(0, END)
		generator_char_req_input.config(fg='black')

def generator_char_req_input_focusout(event):
	if len(generator_char_req_input.get()) == 0:	# checks if entry box is empty
		generator_char_req_input.config(fg='grey')
		generator_char_req_input.insert(0, 'any other required characters?')

def clear_entry_generator_len_req(event):
	if generator_len_req_input.get() == 'how long do you want your password to be?':
		generator_len_req_input.delete(0, END) 
		generator_len_req_input.config(fg='black')

def generator_len_req_input_focusout(event):
	if len(generator_len_req_input.get()) == 0:	# checks if entry box is empty
		generator_len_req_input.config(fg='grey')
		generator_len_req_input.insert(0, 'how long do you want your password to be?')

def clear_entry_checker_password_input(event):
	if checker_password_input.get() == 'Type in your password to check':
		checker_password_input.delete(0, END)
		checker_password_input.config(fg='black') 

def clear_entry_checker_password_input_focusout(event):
	if len(checker_password_input.get()) == 0:	# checks if entry box is empty
		checker_password_input.config(fg='grey')
		checker_password_input.insert(0, 'Type in your password to check')

def clear_entry_checker_char_req(event):
	if checker_char_req_input.get() == 'what character do you want to check?':
		checker_char_req_input.delete(0, END)
		checker_char_req_input.config(fg='black') 

def checker_char_req_input_focusout(event):
	if len(checker_char_req_input.get()) == 0:	# checks if entry box is empty
		checker_char_req_input.config(fg='grey')
		checker_char_req_input.insert(0, 'what character do you want to check?')

char_storage = []
def req_char_storage(event):
	global char_storage

	if len(generator_char_req_input.get()) == 1:
		char_storage.append(str(generator_char_req_input.get()))
	else:
		messagebox.showerror('Input Error', 'input not valid, we only accept single character inputs')
	generator_char_req_input.delete(0, END)
	generator_char_req_input.config(fg='grey')
	generator_char_req_input.insert(0, 'any other required characters?')


generator_frame = LabelFrame(root, text='Password Generator', padx=10, pady=10)
generator_frame.grid(row=0, column=0, padx=10, pady=10)
checker_frame = LabelFrame(root, text='Password Checker', padx=10, pady=10)
checker_frame.grid(row=0, column=1, padx=10, pady=10)

generator_char_req_input = Entry(generator_frame, width=42)
generator_char_req_input.grid(row=0, column=0, padx=5, pady=5)
generator_char_req_input.config(fg='grey')
generator_char_req_input.insert(0, 'what character do you want in your password?')
generator_char_req_input.bind('<FocusIn>', clear_entry_generator_char_req)	# <Button-1> detects left mouseclick
generator_char_req_input.bind('<FocusOut>', generator_char_req_input_focusout)
generator_char_req_input.bind('<KeyPress-Return>', req_char_storage)

generator_len_req_input = Entry(generator_frame, width=39)
generator_len_req_input.grid(row=0, column=1, padx=5, pady=5)
generator_len_req_input.config(fg='grey')
generator_len_req_input.insert(0, 'how long do you want your password to be?')
generator_len_req_input.bind('<FocusIn>', clear_entry_generator_len_req)
generator_len_req_input.bind('<FocusOut>', generator_len_req_input_focusout)


generate_btn = Button(generator_frame, text='generate password', command=lambda: password_generator(*char_storage, length=int(generator_len_req_input.get())))
# *char_storage expands the list to pass through argument similar to parameter *args!
generate_btn.grid(row=1,column=0, columnspan=2)


checker_password_input = Entry(checker_frame, width=36)
checker_password_input.grid(row=0, column=2, padx=5, pady=5)
checker_password_input.config(fg='grey')
checker_password_input.insert(0, 'Type in your password to check')
checker_password_input.bind('<FocusIn>', clear_entry_checker_password_input)
checker_password_input.bind('<FocusOut>', clear_entry_checker_password_input_focusout)

checker_char_req_input = Entry(checker_frame, width=36)
checker_char_req_input.grid(row=0, column=3, padx=5, pady=5)
checker_char_req_input.config(fg='grey')
checker_char_req_input.insert(0, 'what character do you want to check?')
checker_char_req_input.bind('<FocusIn>', clear_entry_checker_char_req)
checker_char_req_input.bind('<FocusOut>', checker_char_req_input_focusout)

check_btn = Button(checker_frame, text='check password', command=lambda: password_checker(checker_password_input.get(), checker_char_req_input.get()))
check_btn.grid(row=1, column=2, columnspan=2)



mainloop()



