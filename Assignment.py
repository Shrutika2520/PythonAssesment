from stdiomask import getpass
import hashlib
import os
import re
clear = lambda: os.system('cls')


def main():
    clear()
    print("MAIN MENU")
    print("---------")
    print()
    print("1 - Register")
    print("2 - Login")
    print()
    while True:
        print()
        userChoice = input("Choose An Option: ")
        if userChoice in ['1', '2']:
            break
    if userChoice == '1':
        Register()
    else:
        Login()

def Register():
    clear()
    print("REGISTER")
    print("--------")
    print()
    while True:
        userName = input("Enter Your Email:").title()
        word="@."
        if len(userName)>=6:
            if userName[0].isalpha():
                if ("@" in userName) and (userName.count("@")==1):
                    if(userName[-4]==".") ^ (userName[-3]=="."):
                        if word in userName:
                            print("Invalid Username")
                        else:
                            print("Valid userName")
                            break
                    else:
                        print("Invalid Username")
                else:
                   print("Invalid Username")
            else:
               print("Invalid Username")
        else:
            print("Invalid Username")
            print()
        error = input("\n\nPress (t) To Try Again:\nPress (m) To Main Menu: ").lower()
        if error == 't':
               Register()
               break
        elif error == 'm':
                main()
                break
        if userName != '':
            break
    userName = sanitizeName(userName)
    if userAlreadyExist(userName):
        displayUserAlreadyExistMessage()
    else:
        while True:
            flag = 0
            userPassword = getpass("Enter Your Password: ")
            if not re.search('[a-z]', userPassword):
                flag = 1
            if not re.search('[0-9]', userPassword):
                flag = 1
            if not re.search('[A-Z]', userPassword):
                flag = 1
            if not re.search('[#@!$]', userPassword):
                flag = 1
            if len(userPassword)<6 or len(userPassword)>16:
                flag = 1
            if (flag == 0):
                print("Strong Password")
            else:
                print("Invalid Password")
                error = input("\n\nPress (t) To Try Again:\nPress (m) To Main Menu: ").lower()
                if error == 't':
                   Register()
                   break
                elif error == 'm':
                   main()
                   break
            if userPassword != '':
                break
        while True:
            confirmPassword = getpass("Confirm Your Password: ")
            if confirmPassword == userPassword:
                break
            else:
                print("Passwords Don't Match")
                print()
        if userAlreadyExist(userName, userPassword):
            while True:
                print()
                error = input("You Are Already Registered.\n\nPress (T) To Try Again:\nPress (L) To Login: ").lower()
                if error == 't':
                    Register()
                    break
                elif error == 'l':
                    Login()
                    break
        addUserInfo([userName, hash_password(userPassword)])

        print()
        print("Registered!")


def Login():
    clear()
    print("LOGIN")
    print("-----")
    print()
    usersInfo = {}
    with open('userInfo.txt', 'r') as file:
        for line in file:
            line = line.split()
            usersInfo.update({line[0]: line[1]})

    while True:
        userName = input("Enter Your Email: ").title()
        userName = sanitizeName(userName)
        if userName not in usersInfo:
            print("You Are Not Registered")
            print()
        else:
            break
    while True:
        userPassword = getpass("Enter Your Password: ")
        if not check_password_hash(userPassword, usersInfo[userName]):
            print("Incorrect Password")
            error = input("\n\nPress (t) To Try Again:\nPress (f) To ForgotPassword: ").lower()
            if error == 't':
              Login()
              break
            elif error == 'f':
              Forgotpassword()
            break
        else:
            break
    print()
    print("Logged In!")

def Forgotpassword():
    clear()
    ACC = True
    while ACC:
     check1 =input("Enter your userName to recover your username or password ")
     with open('userInfo.txt','r') as file:
        for line in file:
            text = line.split()
            if check1 in file:
                print(line)
                ACC= False
                change = input("Do you want to change your password? [y,n]")
                while change not in('y', 'n'):
                    change = input("Do you want to change your password? [y,n]")
                if change == "y":
                    ACC = True
                    with open("userInfo.txt","r+") as file:
                        for line in file:
                            text = line.split()
                            while check:
                                oldpassword = input("Enter old password ")
                                password2 = input("Enter new password ")
                                if len(password2) < 5:
                                    print("New password is too short")
                                flag = 0
                                password2 = getpass("Enter Your Password: ")
                                if not re.search('[a-z]', password2):
                                  flag = 1
                                if not re.search('[0-9]', password2):
                                  flag = 1
                                if not re.search('[A-Z]', password2):
                                  flag = 1
                                if not re.search('[#@!$]', password2):
                                  flag = 1
                                if len(password2)<6 or len(password2)>16:
                                   flag = 1
                                if (flag == 1):
                                  print("Invalid Password")
                                elif oldpassword not in text:
                                    print("Old password is incorrect")
                                elif oldpassword in text:       
                                    s = open("database.txt").read()
                                    s = s.replace(oldpassword, password2)
                                    f = open("userInfo.txt", 'w')
                                    f.write(s)
                                    f.close()
                                    print("Password has been successfully changed")
                                    check = False
                                    break
            elif len(check1) < 32 and (ACC == True):
                print("UserName not found please register again")
                error = input("\n\nPress (t) To Try Again:\nPress (r) To Register Again: ").lower()
                if error == 't':
                  Login()
                  break
                elif error == 'r':
                  Register()
                  break
    
def addUserInfo(userInfo: list):
    with open('userInfo.txt', 'a') as file:
        for info in userInfo:
            file.write(info)
            file.write(' ')
        file.write('\n')

def userAlreadyExist(userName, userPassword=None):
    if userPassword == None:
        with open('userInfo.txt', 'r') as file:
            for line in file:
                line = line.split()
                if line[0] == userName:
                    return True
        return False
    else:
        userPassword = hash_password(userPassword)
        usersInfo = {}
        with open('userInfo.txt', 'r') as file:
            for line in file:
                line = line.split()
                if line[0] == userName and line[1] == userPassword:
                    usersInfo.update({line[0]: line[1]})
        if usersInfo == {}:
            return False
        return usersInfo[userName] == userPassword

def displayUserAlreadyExistMessage():
    while True:
        print()
        error = input("You Are Already Registered.\n\nPress (T) To Try Again:\nPress (L) To Login: ").lower()
        if error == 't':
            Register()
            break
        elif error == 'l':
            Login()
            break

def sanitizeName(userName):
    userName = userName.split()
    userName = '-'.join(userName)
    return userName

def hash_password(password):
    return hashlib.sha256(str.encode(password)).hexdigest()

def check_password_hash(password, hash):
    return hash_password(password) == hash


main()