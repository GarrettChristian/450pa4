package main

import (
	"bufio"
	"fmt"
	"os"

	"./security"
)

// Helper to scan user input with validation that the scanner did not encounter an error
func scanWithValidation(scanner bufio.Scanner) string {
	retString := ""
	scanner.Scan()            // collect user option
	if scanner.Err() != nil { // check that there is no scanner error
		retString = "SCANNER ERROR" // scan
	} else {
		retString = scanner.Text()
	}
	return retString
}

// Wait for the user to press enter before displaying more options used following a successful
func waitForuserInput(scanner bufio.Scanner) {
	enter := "wait for user"
	for enter != "" {
		fmt.Printf("\nPlease press enter to continue: ")
		enter = scanWithValidation(scanner)
	}
}

// Main, holds the for loop & switch statment for operations
func main() {

	if len(os.Args) != 2 {
		fmt.Println("ERROR: Name of the input file not found in the command line arguments")
		os.Exit(1)
	}

	security.CreatePasswordFile()

	if !security.LoadAccessMatrix(os.Args[1]) { // load the input file
		fmt.Println("Couldn't read the input file")
		os.Exit(1)
	}

	scanner := bufio.NewScanner(os.Stdin) // Scanner to read user input
	optionSelected := ""
	for optionSelected != "8" { // Loop until option 14 (exit) is selected

		// presents the user with the menu of choices
		fmt.Printf("\n---------------------------------------\n"+
			"Please select an option:\n"+
			"1) Su – change to another user\n"+
			"2) Chown – change the owner of an object\n"+
			"3) Chgrp – change the group of an object\n"+
			"4) Chmod – change the access rights on an object\n"+
			"5) Groupadd – add a user to a group\n"+
			"6) Groupdel – delete a user from a group\n"+
			"7) Access an object\n"+
			"8) Exit the program\n\n"+
			"Current User: %s\n"+
			"Select: ", security.GetCurrentUser())

		optionSelected = scanWithValidation(*scanner)

		switch optionSelected { // switch on the option selected by the user

		case "1": // Su
			fmt.Println("\n1) Su – change to another user")
			fmt.Print("Please provide a user name: ")
			userName := scanWithValidation(*scanner)
			fmt.Printf("Please provide the password for %s: ", userName)
			password := scanWithValidation(*scanner)
			if security.SetCurrentUser(userName, password) {
				fmt.Printf("Successfully changed the user to: %s\n", userName)
			} else {
				fmt.Printf("Failed to change the user to: %s\n", userName)
			}
			waitForuserInput(*scanner)

		case "2": // Chown
			fmt.Println("\n2) Chown – change the owner of an object")
			fmt.Print("Please provide the user name: ")
			userName := scanWithValidation(*scanner)
			fmt.Print("Please provide the object: ")
			object := scanWithValidation(*scanner)
			if security.Chown(userName, object) {
				fmt.Printf("Successfully changed the owner of: %s to: %s\n", object, userName)
			} else {
				fmt.Printf("Failed to change the owner of: %s to: %s\n", object, userName)
			}
			waitForuserInput(*scanner)

		case "3": // Chgrp
			fmt.Println("\n3) Chgrp – change the group of an object")
			fmt.Print("Please provide the group: ")
			group := scanWithValidation(*scanner)
			fmt.Print("Please provide the object: ")
			object := scanWithValidation(*scanner)
			if security.Chgrp(group, object) {
				fmt.Printf("Successfully changed the group of: %s to: %s\n", object, group)
			} else {
				fmt.Printf("Failed to change the group of: %s to: %s\n", object, group)
			}
			waitForuserInput(*scanner)

		case "4": // Chmod
			fmt.Println("\n4) Chmod – change the access rights on an object")
			fmt.Print("Please provide the object: ")
			object := scanWithValidation(*scanner)
			fmt.Print("Please provide the access rights: ")
			accessRights := scanWithValidation(*scanner)
			if security.Chmod(object, accessRights) {
				fmt.Printf("Successfully changed the access rights of: %s to: %s\n", object, accessRights)
			} else {
				fmt.Printf("Failed to change the access rights of: %s to: %s\n", object, accessRights)
			}
			waitForuserInput(*scanner)

		case "5": // Groupadd
			fmt.Println("\n5) Groupadd – add a user to a group")
			fmt.Print("Please provide the user name: ")
			userName := scanWithValidation(*scanner)
			fmt.Print("Please provide the group: ")
			group := scanWithValidation(*scanner)
			if security.Groupadd(userName, group) {
				fmt.Printf("Successfully added: %s to: %s\n", userName, group)
			} else {
				fmt.Printf("Failed to add: %s to: %s\n", userName, group)
			}
			waitForuserInput(*scanner)

		case "6": // Groupdel
			fmt.Println("\n6) Groupdel – delete a user from a group")
			fmt.Print("Please provide the user name: ")
			userName := scanWithValidation(*scanner)
			fmt.Print("Please provide the group: ")
			group := scanWithValidation(*scanner)
			if security.Groupdel(userName, group) {
				fmt.Printf("Successfully deleteted: %s from: %s\n", userName, group)
			} else {
				fmt.Printf("Failed to delete: %s from: %s\n", userName, group)
			}
			waitForuserInput(*scanner)

		case "7": // Access Object
			fmt.Println("\n7) Access an object")
			fmt.Print("Please provide the object: ")
			object := scanWithValidation(*scanner)
			fmt.Print("Please provide the access method: ")
			accessMethod := scanWithValidation(*scanner)
			if security.Access(object, accessMethod) {
				fmt.Printf("Successfully accessed: %s with: %s\n", object, accessMethod)
			} else {
				fmt.Printf("Failed to access: %s with: %s\n", object, accessMethod)
			}
			waitForuserInput(*scanner)

		case "8": // Exit the program
			fmt.Println("\n8) Exit the program")
			fmt.Println("Exiting\nThank you")

		default:
			fmt.Printf("\nThere was an issue with your input \"%s\" \nPlease try again\n", optionSelected)
			waitForuserInput(*scanner)
		}

	}
}
