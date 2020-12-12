# 450pa4
CS450 – Project #4

# Operating Systems CS450 Project 4
Name: Garrett Christian

___

In project 4 I have created a program that allows the user to manipulate the access rights for objects and enforces those access rights.

My program will be given a text file of exactly 10 lines taken from a filename as a
parameter on the command line. The input file will list all of the objects in the system – one per line. For each object, there will be 3
entries representing the object’s:
- Name
- Owner
- Group

There are no objects except those listed in the input file. There is always a user named “root” that has all access rights to all objects
(regardless of what the access rights say). Other than “root” and the users listed in the input file, there are no other users. There is always
a group named “root”, and other than “root” and the groups listed in the input file, there are no other groups. Initially, no user has access
to any object (i.e. the access rights for all objects are 000) and no user is in any group.

___

## Compiling:

make

## Running

./p4 INPUT_FILE_NAME

example:
- make
- ./p4 input.txt

## Known Bugs:

None.

___

## Passwords (extra credit)

All passwords are the username of the user you'd like to change to

- U1: U1
- U2: U2
- U3: U3
- U4: U4
- U5: U5
- U6: U6
- U7: U7
- U8: U8
- U9: U9
- U10: U10
- root: root

The hash is stored in the file "password" and compared with the hash of your provided password

___

## Overview of options
Below are 8 potential options after you boot up the program:

1) Su – change to another user
2) Chown – change the owner of an object
3) Chgrp – change the group of an object
4) Chmod – change the access rights on an object
5) Groupadd – add a user to a group
6) Groupdel – delete a user from a group
7) Access an object
8) Exit the program

___

### **1) Su – change to another user**

For su you'll be prompted for a user name and a password associated with that username. If it exists and the hash of the provided password using SHA-256 matches the hash stored in the password file that should become the current user who is issuing commands.

> - Successfully changed the user to: username
> - Failed to change the user to: username

This is done using security.go's SetCurrentUser function

Possible Error messages:
> - ERROR: couldn't find the user username
> - ERROR: couldn't open the file password
> - ERROR: couldn't read from the file password
> - EERROR: the password hash is not found in the password hash file for user username
> - ERROR: the passwords hash does not match
___

### **2) Chown – change the owner of an object**

For chown you'll be prompted for the username and object. If both exist you should set the user to be the owner of the object (overwriting the existing owner). This operation can only be performed if the current user who is issuing commands is “root”.

> - Successfully changed the owner of: object to: username
> - Failed to change the owner of: object to: username

This is done using security.go's Chown function

Possible Error messages:
> - ERROR: current user needs to be root is currently: currentUser
> - ERROR: ERROR: object object is not found in the object list
> - ERROR: couldn't find the user username
___

### **3) Chgrp – change the group of an object**

For chgrp you'll be prompted for the group and object. If both exist you should set the group associated with the object (overwriting the existing group). This operation can only be performed if the current user who is issuing commands is the owner of the object (or is “root”).

> - Successfully changed the group of: object to: group
> - Failed to change the group of: object to: group

This is done using security.go's Chgrp function

Possible Error messages:
> - ERROR: ERROR: object object is not found in the object list
> - ERROR: group group is not found in the group list
> - ERROR: user needs to be root user or the owner of the object (currentOwner) currently: currentUser
___

### **4) Chmod – change the access rights on an object**

For chmod you'll be prompted for an object and the access rights (a three-digit octal number - see the linux man page for chmod if you need help). If the object exists and the access rights are valid, you should set the access rights for the object to the specified value. This operation can only be performed if the current user who is issuing commands is the owner of the object (or is “root”). This affects all users of the object.

> - Successfully changed the access rights of: object to: accessRights
> - Failed to change the access rights of: object to: accessRights

This is done using security.go's Chmod function

Possible Error messages:
> - ERROR: ERROR: object object is not found in the object list
> - ERROR: user needs to be root user or the owner of the object (currentOwner) currently: currentUser
> - ERROR: couldn't convert the access rights to an integer
> - ERROR: accessRight is not valid as an access right
___

### **5) Groupadd – add a user to a group**

For groupadd you'll be prompted for a user name and a group. If both exist and the user is not already a member of the specified
group, you should add the specified user to the specified group. A user can be in multiple groups so this operation adds another
group to the list of a user’s groups. This operation can only be performed if the current user who is issuing commands is 
“root”.

> - Successfully added: username to: group
> - Failed to add: username to: group

This is done using security.go's Groupadd function

Possible Error messages:
> - ERROR: user needs to be root user currently: currentUser
> - ERROR: couldn't find the user username
> - ERROR: group group is not found in the group list
> - ERROR: username is already in the group 
___

### **6) Groupdel – delete a user from a group**

For groupdel you'll be prompted for a user name and a group. If both exist and the user is a member of the specified group, you
should delete the specified user from the specified group. This operation can only be performed if the current user who is
issuing commands is “root”.

> - Successfully deleteted: username from: group
> - Failed to deletete: username from: group

This is done using security.go's Groupdel function

Possible Error messages:
> - ERROR: user needs to be root user currently: currentUser
> - ERROR: couldn't find the user username
> - ERROR: group group is not found in the group list
> - ERROR: couldn't find username in the group group
___

### **7) Access an object**

Prompt for an object and access method. If the object exists and the access method is one of “R”, “W”, or “X”, check to see if
the current user issuing commands has the appropriate permissions to access the specified object in the specified manner. If the
current user issuing commands is the owner of the object then the “owner” rights are the ones you should use to decide whether
or not the user has access. If the current user issuing commands is not the owner of the object but is in the same group as the
object then the “group” rights are the ones you should use to decide whether or not the user has access. If the current user
issuing commands is not the owner of the object and is not in the same group as the object then the “world” rights are the ones
you should use to decide whether or not the user has access. The user named “root” that has all access rights to all objects
(regardless of what the access rights say). Notify the user of your program whether the attempted access
succeeded or failed.

> - Successfully accessed: object with: accessMethod
> - Failed to access: object with: accessMethod

This is done using security.go's Access function

Possible Error messages:
> - ERROR: ERROR: object object is not found in the object list
> - ERROR: accessMethod is not R, W, or X
> - ERROR: user currentUser with access accessMethod is not able to access object fullAccessRights based on accessRightsBeingUsed
___

### **8) Exit the program**

Exits the program

___

### Helper functions

- GetCurrentUser, Returns the current user
- hashPassword, Hashes the string using SHA 256
- userExistsInGroup, helper to see if the user exists in the group returns min int if not found otherwise returns the index
- digit, helper to get the digit from the int to check the rights

___
