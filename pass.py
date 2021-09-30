import sqlite3, hashlib
from tkinter import *
from tkinter import simpledialog
from tkinter import ttk
from functools import partial

#Database Code
with sqlite3.connect("password_safe.db") as db:
    cursor = db.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS master(
id INTEGER PRIMARY KEY,
password NOT NULL);
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS safe(
id INTEGER PRIMARY KEY,
website TEXT NOT NULL,
username TEXT NOT NULL,
password TEXT NOT NULL);
""")

back = '#ADD8E6'

def put(text1,text2,text3):
    answer1 = simpledialog.askstring("Input", text1)
    answer2 = simpledialog.askstring("Input", text2)
    answer3 = simpledialog.askstring("Input", text3)
    return [answer1,answer2,answer3]

#GUI
root = Tk()
root.title("Password Manager")

def hashPassword(input):
    hash = hashlib.md5(input)
    hash = hash.hexdigest()

    return hash


def firstScreen():
    root.geometry("270x150")
    root['bg'] = back

    lbl = Label(root,text = "Create Master Password")
    lbl.config(anchor = CENTER, bg = back)
    lbl.pack()

    txt = Entry(root, width = 20)
    txt.pack()
    txt.focus()

    lbl1 = Label(root, text = "Re-Enter Password")
    lbl1.config(bg = back)
    lbl1.pack()

    txt1 = Entry(root, width = 20)
    txt1.pack()

    lbl2 = Label(root)
    lbl2.config(bg = back)
    lbl2.pack()

    def savePassword():
        if txt.get() == txt1.get():
            hashedPassword = hashPassword(txt.get().encode('utf-8'))
            insert_password = """ INSERT INTO master(password)
            VALUES(?) """
            cursor.execute(insert_password, [(hashedPassword)])
            db.commit()

            passwords()
        else:
            lbl2.config(text = "Passwords Do Not Match")


    btn = Button(root, text = "Save", command = savePassword, width = 15)
    btn.pack(pady = 5)

def loginScreen():
    root.geometry("270x100")
    root['bg'] = back

    lbl = Label(root,text = "Enter Master Password")
    lbl.config(anchor = CENTER, bg = back)
    lbl.pack()

    txt = Entry(root, width = 20, show = "*")
    txt.pack()
    txt.focus()

    lbl1 = Label(root)
    lbl1.config(bg = back)
    lbl1.pack()

    def getMasterPassword():
        checkHashedPassword = hashPassword(txt.get().encode('utf-8'))
        cursor.execute("SELECT * FROM master where id = 1 AND password = ?",[(checkHashedPassword)])
        print(checkHashedPassword)
        return cursor.fetchall()

    def checkPassword():
        match = getMasterPassword()

        print(match)

        if match:
            passwords()
        else:
            txt.delete(0,'end')
            lbl1.config(text = "Wrong Password")


    btn = Button(root, text = "Submit", command = checkPassword, width = 15)
    btn.pack(pady = 5)

def passwords():
    for widget in root.winfo_children():
        widget.destroy()
    
    def addEntry():
        ins = put("Website Name","Username or Email","Password")

        insert_fields = """ INSERT INTO safe(website,username,password)
        VALUES(?, ?, ?) """
        
        cursor.execute(insert_fields, (ins[0], ins[1], ins[2]))
        db.commit()

        passwords()


    def deleteEntry(input):
        cursor.execute("DELETE FROM safe WHERE id = ?", (input,))
        db.commit()

        passwords()

    def editEntry(input):
        ins = put("Website Name","Username or Email","Password")

        cursor.execute("UPDATE safe SET website = ?, username = ?, password = ? WHERE id = ?", (ins[0],ins[1],ins[2],input,))
        db.commit()

        passwords()

    root.geometry("650x500")

    lbl = Label(root, text = "Vault", bg = back)
    lbl.grid(column = 2)

    btn = Button(root, text = "Add", command = addEntry)
    btn.grid(column= 2, pady= 10)

    lbl = Label(root, text = "Website", bg = back)
    lbl.grid(row = 2, column = 1, padx = 60)
    lbl = Label(root, text = "Username", bg = back)
    lbl.grid(row = 2, column = 2, padx = 60)
    lbl = Label(root, text = "Password", bg = back)
    lbl.grid(row = 2, column = 3, padx = 60)

    cursor.execute("SELECT * FROM safe")
    if (cursor.fetchall() != None):
        i = 0
        while True:
            cursor.execute("SELECT * FROM safe")
            array = cursor.fetchall()

            lbl1 = Label(root, text = array[i][1],font = ("Arial", 12), bg = back)
            lbl1.grid(column = 1, row = i+3)
            lbl2 = Label(root, text = array[i][2],font = ("Arial", 12), bg = back)
            lbl2.grid(column = 2, row = i+3)
            lbl3 = Label(root, text = array[i][3],font = ("Arial", 12), bg = back)
            lbl3.grid(column = 3, row = i+3)

            btn = Button(root, text = "Edit", command = partial(editEntry, array[i][0]))
            btn.grid(column = 4,row = i+3, padx = 15, pady = 5)

            btn = Button(root, text = "Delete", command = partial(deleteEntry, array[i][0]))
            btn.grid(column = 5,row = i+3, pady = 5)

            i = i + 1

            cursor.execute("SELECT * FROM safe")
            if (len(cursor.fetchall()) <= i):
                break

        

cursor.execute("SELECT * FROM master")
if cursor.fetchall():
    loginScreen()
else:
    firstScreen()

root.mainloop()