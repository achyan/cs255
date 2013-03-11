#import hashlib
import bcrypt

f = open('../passwords.txt', 'r')

# assume correct format (2 lines)
adminPwd = f.readlines()[1]
print adminPwd

f.close()

salt = bcrypt.gensalt()
hashed = bcrypt.hashpw('adminPassword', salt)

print hashed

# writing pwdFile
f = open('../../pwdFile', 'w')
f.write(hashed)
f.close()