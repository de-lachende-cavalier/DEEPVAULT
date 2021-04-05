REGISTRATION
============
**User**: inputs username and password

**Server**: saves the password hash in the database and creates a token (UTK) based on the username, which it then sends to the user

FIRST LOGIN
===========
**User**: inputs user-token(UTK) and password inserted at registration

**Server**: validates UTK in the clear and the password based on the hashed version on the server

                    if both valid:
                        user is granted access 
                        the server encrypts the password hash (plus a timestamp for freshness) with a random fernet key 
                        and sends the encrypted message to the user -> this will become the password for further logins
                    else:
                        the user is denied access

OTHER LOGINS
============
**User**: inputs UTK and Fernet encrypted password

**Server**: validates UTK and decrypts Fernet cipher-text to check it against the password hash in the database
                
                    if both valid:
                        user is granted access 
                        the server generates a new Fernet password with a new key and sends it to the user
                    else:
                        the user is denied access


***Why complicate authentication with the Fernet token?*** 
Although the site is hosted on a .onion service and it implements strong HTTPS, I wanted some protection against a 
capable and very motivated attacker, something like an APT, and seeing as I couldn't do any client side encryption or
hashing to not have the password transit in the clear I came up with this system. It's a bit of a hassle for the user
but it provides quite a bit of extra security, seeing as even if the Fernet token were intercepted in traffic the attacker
wouldn't know the key with which it was encrypted, and even if he knew the key he couldn't get the passsword because I
encrypt the hash. On top of that, the attacker can't simply reuse the token to login because as soon as the user logs in
the previous token becomes invalid (due to the timestamp).

 
