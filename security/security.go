package security

import (
	"crypto/sha256"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
)

const PASSWORD_FILE = "password"

var groupUsers map[string][]string
var objectGroup map[string]string
var objectOwner map[string]string
var setOfUsers map[string]struct{}
var objectList []string
var userList []string
var permissionsMatrix [11][10]int
var currentUser string

// The input file will list all of the objects in the system –
// one per line. For each object, there will be 3
// entries representing the object’s: name, owner, and group
func LoadAccessMatrix(inputFile string) bool {

	file, err := os.Open(inputFile) // Open the file for read access.
	if err != nil {
		fmt.Printf("ERROR: couldn't open the file %s\n", inputFile)
		return false
	}
	defer file.Close()

	output := make([]byte, 100) // read from the file (full size)
	amountRead, err := file.Read(output)
	if err != nil {
		fmt.Printf("ERROR: couldn't read from the file %s\n", inputFile)
		return false
	}
	read := string(output[:amountRead])    // convert to a string
	readSplit := strings.Split(read, "\n") // split on the newlines

	// intialize the maps
	groupUsers = make(map[string][]string)
	objectOwner = make(map[string]string)
	objectGroup = make(map[string]string)
	setOfUsers = make(map[string]struct{})

	fmt.Printf("Read from %s: \n", inputFile)
	for _, object := range readSplit { // for each line of the input file
		fmt.Printf("%s\n", object)

		s := strings.Split(object, " ") //split on white space

		objectList = append(objectList, s[0]) // add the object to the slice of objects
		if _, ok := setOfUsers[s[1]]; !ok {   // see if the user already exists
			userList = append(userList, s[1]) // add to the slice of avaliable users
		}
		setOfUsers[s[1]] = struct{}{} // add to the set of users
		objectOwner[s[0]] = s[1]      // set the owner of the object
		objectGroup[s[0]] = s[2]      // set the group of the object

		if _, ok := groupUsers[s[2]]; !ok || userExistsInGroup(s[1], s[2]) != math.MinInt64 { // make sure it isn't already in the group
			groupUsers[s[2]] = append(groupUsers[s[2]], s[1]) // add the user to the group
		}
	}

	groupUsers["root"] = append(groupUsers["root"], "root") // create the root group
	userList = append(userList, "root")                     // add the user root
	setOfUsers["root"] = struct{}{}                         // add root to the set of users

	currentUser = "root" // set the initial user to root
	return true
}

// If it exists that should become the current user who is issuing commands
func SetCurrentUser(userName string, password string) bool {

	if _, ok := setOfUsers[userName]; !ok { // validate the user exists
		fmt.Printf("ERROR: couldn't find the user %s\n", userName)
		return false
	}

	passwordHash := hashPassword(password) // hash the provided password

	file, err := os.Open(PASSWORD_FILE) // Open the password file for read access.
	if err != nil {
		fmt.Printf("ERROR: couldn't open the file %s\n", PASSWORD_FILE)
		return false
	}
	defer file.Close()

	output := make([]byte, 1000)
	amountRead, err := file.Read(output) // Read the password hashes
	if err != nil {
		fmt.Printf("ERROR: couldn't read from the file %s\n", PASSWORD_FILE)
		return false
	}
	read := string(output[:amountRead])
	readSplit := strings.Split(read, "\n")

	actualHash := "NOT FOUND!!!!!"
	for _, object := range readSplit { // go through the potential password hashes

		s := strings.Split(object, " ") // split on white space
		if userName == s[0] {
			actualHash = s[1] // hash for this username
		}
	}

	if actualHash == "NOT FOUND!!!!!" { // make sure the hash exists in the file
		fmt.Println("ERROR: the password hash is not found in the password hash file for user %s", userName)
		return false
	}

	if passwordHash != actualHash { // check the provided password hash vs the actual
		fmt.Println("ERROR: the passwords hash does not match")
		return false
	}

	currentUser = userName // set the new current user
	return true
}

// If both exist you should set the user to be the owner of the object
// (overwriting the existing owner). This operation can only be performed if the current user who is issuing commands is
// “root”.
func Chown(userName string, object string) bool {

	if currentUser != "root" { // make sure they're root
		fmt.Printf("ERROR: current user needs to be root is currently: %s\n", currentUser)
		return false
	}

	if _, ok := objectOwner[object]; !ok { // make sure the object exists
		fmt.Printf("ERROR: object %s is not found in the object list\n", object)
		return false
	}

	if _, ok := setOfUsers[userName]; !ok { // validate the user exists
		fmt.Printf("ERROR: couldn't find the user %s\n", userName)
		return false
	}

	objectOwner[object] = userName
	return true
}

// If both exist you should set the group associated with the object
// (overwriting the existing group). This operation can only be performed if the current user who is issuing commands is the
// owner of the object (or is “root”).
func Chgrp(group string, object string) bool {

	if _, ok := objectOwner[object]; !ok { // make sure the object exists
		fmt.Printf("ERROR: object %s is not found in the object list\n", object)
		return false
	}

	if _, ok := groupUsers[group]; !ok { // make sure the group exists
		fmt.Printf("ERROR: group %s is not found in the group list\n", group)
		return false
	}

	if currentUser != "root" && currentUser != objectOwner[object] {
		fmt.Printf("ERROR: user needs to be root user or the owner of the object (%s) currently: %s\n", objectOwner[object], currentUser)
		return false
	}

	objectGroup[object] = group
	return true
}

// If the object exists and the access rights are valid, you should set the access rights for the object to the
// specified value. This operation can only be performed if the current user who is issuing commands is the owner of the
// object (or is “root”).
func Chmod(object string, accessRight string) bool {

	if _, ok := objectOwner[object]; !ok { // make sure the object exists
		fmt.Printf("ERROR: object %s is not found in the object list\n", object)
		return false
	}

	if currentUser != "root" && currentUser != objectOwner[object] {
		fmt.Printf("ERROR: user needs to be root user or the owner of the object (%s) currently: %s\n", objectOwner[object], currentUser)
		return false
	}

	accessRightsInt, err := strconv.Atoi(accessRight) // convert to access rights to an int
	if err != nil {
		fmt.Printf("ERROR: couldn't convert the access rights to an integer\n")
		return false
	}

	worldVal := digit(accessRightsInt, 1) >= 0 && digit(accessRightsInt, 1) <= 7             // is between 0-7
	groupVal := digit(accessRightsInt, 2) >= 0 && digit(accessRightsInt, 2) <= 7             // is between 0-7
	ownerVal := digit(accessRightsInt, 3) >= 0 && digit(accessRightsInt, 3) <= 7             // is between 0-7
	if accessRightsInt > 777 || accessRightsInt < 0 || !worldVal || !groupVal || !ownerVal { // check the access rights validity
		fmt.Printf("ERROR: %d is not valid as an access right\n", accessRightsInt)
		return false
	}

	var col int = math.MaxInt64

	for index, _ := range objectList { // get the index of the object column
		if objectList[index] == object {
			col = index
		}
	}
	for index, _ := range userList { // for every user set the access rights
		permissionsMatrix[index][col] = accessRightsInt
	}

	return true
}

// If both exist and the user is not already a member of the specified
// group, you should add the specified user to the specified group. A user can be in multiple groups so this operation adds another
// group to the list of a user’s groups. This operation can only be performed if the current user who is issuing commands is
// “root”.
func Groupadd(userName string, group string) bool {

	if currentUser != "root" { // validate the current user is root
		fmt.Printf("ERROR: user needs to be root user currently: %s\n", currentUser)
		return false
	}

	if _, ok := setOfUsers[userName]; !ok { // validate the user exists
		fmt.Printf("ERROR: couldn't find the user %s\n", userName)
		return false
	}

	if _, ok := groupUsers[group]; !ok { // make sure the group exists
		fmt.Printf("ERROR: group %s is not found in the group list\n", group)
		return false
	}

	if math.MinInt64 != userExistsInGroup(userName, group) { // user is found in the group
		fmt.Printf("ERROR: %s is already in the group %s\n", userName, group)
		return false
	}

	groupUsers[group] = append(groupUsers[group], userName) // add the user to the group
	return true
}

// If both exist and the user is a member of the specified group, you
// should delete the specified user from the specified group. This operation can only be performed if the current user who is
// issuing commands is “root”.
func Groupdel(userName string, group string) bool {

	if currentUser != "root" {
		fmt.Printf("ERROR: user needs to be root user currently: %s\n", currentUser)
		return false
	}

	if _, ok := setOfUsers[userName]; !ok { // validate the user exists
		fmt.Printf("ERROR: couldn't find the user %s\n", userName)
		return false
	}

	if _, ok := groupUsers[group]; !ok { // make sure the group exists
		fmt.Printf("ERROR: group %s is not found in the group list\n", group)
		return false
	}

	index := userExistsInGroup(userName, group)
	if math.MinInt64 == index { // make sure user is found in the group
		fmt.Printf("ERROR: couldn't find %s in the group %s\n", userName, group)
		return false
	}

	groupUsers[group] = append(groupUsers[group][:index], groupUsers[group][index+1:]...) // remove the user
	return true
}

// Prompt for an object and access method. If the object exists and the access method is one of “R”, “W”, or “X”, check to see if
// the current user issuing commands has the appropriate permissions to access the specified object in the specified manner. If the
// current user issuing commands is the owner of the object then the “owner” rights are the ones you should use to decide whether
// or not the user has access. If the current user issuing commands is not the owner of the object but is in the same group as the
// object then the “group” rights are the ones you should use to decide whether or not the user has access. If the current user
// issuing commands is not the owner of the object and is not in the same group as the object then the “world” rights are the ones
// you should use to decide whether or not the user has access. Notify the user of your program whether the attempted access
// succeeded or failed.
func Access(object string, accessMethod string) bool {

	if _, ok := objectOwner[object]; !ok { // make sure the object exists
		fmt.Printf("ERROR: object %s is not found in the object list\n", object)
		return false
	}

	// Get the rights of the specified object
	var col int = math.MaxInt64
	var row int = math.MaxInt64
	for index, _ := range objectList { // get the index of the object column
		if objectList[index] == object {
			col = index
		}
	}
	for index, _ := range userList { // for every user set the access rights
		if userList[index] == currentUser {
			row = index
		}
	}
	rights := permissionsMatrix[row][col]

	specificRights := 0
	if currentUser == objectOwner[object] {
		// If the current user issuing commands is the owner of the object then the “owner” rights are the ones you should use
		specificRights = digit(rights, 3)
	} else if userExistsInGroup(objectGroup[object], currentUser) != math.MinInt64 {
		// If the current user issuing commands is not the owner of the object but is in the same group as the
		// object then the “group” rights are the ones you should use
		specificRights = digit(rights, 2)
	} else {
		// If the current user issuing commands is not the owner of the object and is not in the same group as the object
		// then the “world” rights are the ones you should use
		specificRights = digit(rights, 1)
	}

	success := false
	switch accessMethod {
	case "R":
		success = (specificRights >= 4 && specificRights <= 7) || currentUser == "root"
	case "W":
		success = (specificRights == 2 || specificRights == 3 || specificRights == 6 || specificRights == 7 || currentUser == "root")
	case "X":
		success = (specificRights == 1 || specificRights == 3 || specificRights == 5 || specificRights == 7 || currentUser == "root")
	default:
		fmt.Printf("ERROR: %s is not R, W, or X\n", accessMethod)
	}

	if !success {
		fmt.Printf("ERROR: user %s with access %s is not able to access %s %d based on %d \n", currentUser, accessMethod, object, rights, specificRights)
	}
	return success
}

// The function used in generating the hashed passwords
func CreatePasswordFile() bool {
	file, err := os.Create(PASSWORD_FILE)
	if err != nil {
		fmt.Printf("ERROR: couldn't create the password file\n")
		return false
	}
	defer file.Close()

	for i := 1; i < 11; i++ {
		userName := fmt.Sprintf("U%d ", i) // given U1-U10
		password := fmt.Sprintf("U%d", i)  // password is the same as username U1 = U1

		file.WriteString(userName)
		file.WriteString(hashPassword(password))
		file.WriteString("\n")
	}
	file.WriteString("root ")
	file.WriteString(hashPassword("root"))

	return true
}

// Returns the current user
func GetCurrentUser() string {
	return currentUser
}

// Hashes the string using SHA 256
func hashPassword(password string) string {
	h := sha256.New()
	h.Write([]byte(password))
	hash := fmt.Sprintf("%x", h.Sum(nil))

	return hash
}

// helper to see if the user exists in the group
// returns min int if not found otherwise returns the index
func userExistsInGroup(user string, group string) int {
	loc := math.MinInt64
	for index, _ := range groupUsers[group] { // iterate through the users in the group to find the index
		if groupUsers[group][index] == user {
			loc = index
		}
	}

	return loc
}

// helper to get the digit from the int to check the rights
func digit(num int, place int) int {
	r := num % int(math.Pow(10, float64(place)))
	return r / int(math.Pow(10, float64(place-1)))
}
